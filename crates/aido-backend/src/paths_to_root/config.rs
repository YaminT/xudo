//! sudoers and doas configuration, read for the one thing that matters here:
//! a rule that runs as root without a password.
//!
//! **Not a parser.** sudo's grammar has aliases, negation, digests, and
//! escapes, and getting any of it subtly wrong in a parser would produce a
//! confident wrong answer. This reads lines and looks for tokens, and every
//! choice it makes errs towards reporting:
//!
//! * A line is a whole-line comment only when its first non-blank byte is `#`
//!   and it is not an include directive or a `#<uid>` user. A `#` later in a
//!   line does not hide a tag on it: the whole line is read.
//! * **A line that ends in a backslash is never modelled.** sudo (`toke.l`)
//!   and `OpenDoas` (`yylex`) each decide whether a trailing backslash joins
//!   the next line by what precedes it (an escape, a comment, a quote, a token
//!   under way, a carriage return), and four rounds of review each found
//!   another case where this module and the real lexer disagreed (verified
//!   against sudo 1.9.16p2 and `OpenDoas` 6.8.2). So the decision, recorded in
//!   `docs/CONCERNS.md`, is to stop modelling continuations: every physical
//!   line whose last byte, past trailing whitespace, is a backslash (whatever
//!   precedes it, in either dialect, a whole-line comment included) makes what
//!   it may join **unmodelled**. Every rule on that logical line, and on the
//!   line after a comment that ends in a backslash, is `Scope::Unknown`
//!   (reported "maybe", never "no"); a `NOPASSWD`, `!authenticate` or `nopass`
//!   anywhere in the joined text counts, whatever kind of statement the line
//!   was taken for and even where a word is split across the join (`OpenDoas`
//!   reads `permit nopass 10\` then `00` as uid 1000, and `:2\` then `7` as
//!   gid 27); and the file is listed as unverified, so its check is never
//!   clean: found where a rule is found, unverified where none is.
//! * **An include on a line aido does not model is reported as an include,
//!   whatever else is found.** An include path is the one token sudo reads
//!   with a final backslash in it: `@include /p\` opens the file named `p\`
//!   (and the line after it is a rule of its own), while `@include /p \` ends
//!   the path at the blank, and the backslash continues. So each physical line
//!   of a joined line is read twice, with its trailing backslash cut off and as
//!   written (`/p` and `/p\`; for `/p\ `, a backslash and a blank, which is
//!   an escaped blank in the name, `/p` and `/p `), for `@include`, `#include`,
//!   `@includedir` and `#includedir`, on the first line or a later one (sudo
//!   honours an include on the line after `lecture_file=/etc/x\ `, which it
//!   does not join); a path that is not there is reported as unverified.
//!
//!   **Those paths are hints, not necessarily the file sudo opens**, and two
//!   shapes show it: a backslash-newline *inside the quotes* of an include path
//!   is dropped and the path goes on (`@include "/etc/s4/a\` then `b"` opens
//!   `/etc/s4/ab`, `toke.l` line 786 and the `<GOTINC>` state), and an include
//!   path may *start on the continuation line* of its directive (`@include\`
//!   then `/etc/s6/a\`, `toke.l` lines 173 and 858). Every further shape is
//!   another round of review, and this module has stopped chasing them. The
//!   guarantee is a containment instead: **a line that is not settled and holds
//!   the word `include`, in a physical line or across a join, is a finding of
//!   its own** (`Grant::Include`, scope unknown, so "maybe", and `"grant":
//!   "include"` on the wire), on the physical line that holds the word. The
//!   report can then never show only "names others" while an include it could
//!   not read stands, and the check is never clean. A settled include on a
//!   modelled line adds nothing. `OpenDoas` has no include directive, so
//!   nothing changes for doas.
//!
//!   Adversarial tests, each with an end-to-end twin in `tests.rs`:
//!   `denies_any_line_ending_in_a_backslash_hiding_the_callers_nopasswd_rule`
//!   (twin: `..._passwordless_rule`, a property over every generated head and
//!   every spelling of a rule that names the caller),
//!   `denies_a_trailing_backslash_in_an_include_path_absorbing_the_callers_rule`,
//!   `denies_an_include_path_keeping_its_backslash_hiding_the_file_sudo_opens`
//!   (twin: `denies_an_include_path_ending_in_a_backslash_crediting_the_callers_grant_to_the_plain_named_file`),
//!   `denies_an_include_on_a_later_line_keeping_its_backslash_hiding_the_file_sudo_opens`
//!   (with a CRLF twin),
//!   `denies_an_include_continued_inside_its_quotes_hiding_the_file_sudo_opens`,
//!   `denies_an_include_path_starting_on_a_continuation_line_hiding_the_file_sudo_opens`,
//!   `denies_an_include_directive_split_across_a_join_hiding_its_file`
//!   (twin: `denies_an_include_sudo_reads_from_a_file_aido_did_not_open_hiding_the_callers_grant`
//!   and a property over every generated head),
//!   `denies_an_include_on_a_line_the_program_did_not_join_hiding_the_callers_grant`
//!   and `denies_a_continuation_splitting_a_doas_identity_as_another_users`.
//!   This is a containment, not a fix: reading the program's own answer for the
//!   caller (`doas -C <file> <cmd>`, `sudo -l -U <user>`) is plan item D3
//!   (`docs/todo/m2b-finish-plan.md`), and replaces this reader, and the
//!   include finding, where it can run.
//! * Within one physical line the scan is left to right with escape semantics,
//!   for tag and comment detection (see `read_line`): a `#` ends the part of
//!   the line that counts as text for a comment, except in sudo a `#<digit>`
//!   or `#-<digit>` id, and `OpenDoas` has no such exception.
//! * **Exactly these escapes are modelled**: a backslash before a backslash
//!   (`\\` is one literal backslash), before a `#` (not a comment), and before
//!   a blank (an escaped blank). **Everything else is unmodelled**: a
//!   backslash before any other byte (`\q`, `\xHH`, `\"`, `\r`), and a double
//!   quote on a line that also has a backslash or a `#` past its first byte.
//!   Such a line makes the file unverified, and every rule on a logical line it
//!   is part of is reported as naming someone aido cannot resolve ("maybe"),
//!   not as another user's. `OpenDoas` drops the backslash of an escape, so
//!   `nopas\s` is the keyword `nopass` to it (and grants); a doas line with an
//!   unmodelled escape is therefore searched for `nopass` as written and with
//!   its backslashes removed
//!   (`denies_a_doas_keyword_spelled_with_an_escape_hiding_the_callers_rule`).
//!   The adversarial tests are
//!   `an_unmodelled_construct_makes_what_it_could_join_unknown_never_clean`
//!   and, end to end,
//!   `an_unmodelled_construct_cannot_make_the_passwordless_check_clean`.
//!   Nothing beyond this is claimed about which lines sudo or `OpenDoas` joins.
//! * `NOPASSWD`, `!authenticate`, and `nopass` are found as whole words
//!   anywhere in a live line, whatever surrounds them. `!authenticate` is
//!   looked for on every line, not only on `Defaults`; off a `Defaults` line
//!   it names nobody it can read, which is reported as "maybe".
//!
//! Bytes throughout: a configuration file is not guaranteed to be UTF-8, and a
//! lossy conversion here could split a token in two.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// What removes the password from a rule, or marks a place where what a rule
/// grants is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Grant {
    /// The sudoers `NOPASSWD:` tag.
    Nopasswd,
    /// The sudoers `!authenticate` default, which removes the password from
    /// every rule it covers.
    NoAuthenticate,
    /// The doas `nopass` option.
    Nopass,
    /// An include on a line aido does not model. The file the program opens
    /// may not be one aido read, so what it grants is unknown. Not a grant: a
    /// marker, always reported as "maybe".
    Include,
}

/// Who a rule names, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    /// Everyone: a global `Defaults`.
    Everyone,
    /// A sudoers user list, item by item.
    Users(Vec<Vec<u8>>),
    /// A doas identity: `user`, `:group`, or either by number.
    DoasIdentity(Vec<u8>),
    /// Something this reader does not resolve.
    Unknown,
}

/// One rule that removes the password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuleLine {
    /// Its first physical line, counting from 1.
    pub(super) line: usize,
    /// The rule, continuation lines joined with a space.
    pub(super) text: Vec<u8>,
    /// What removes the password.
    pub(super) grant: Grant,
    /// Who it names.
    pub(super) scope: Scope,
}

/// An include directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Include {
    /// `#include` / `@include`: one file.
    File(Vec<u8>),
    /// `#includedir` / `@includedir`: every eligible file in a directory.
    Dir(Vec<u8>),
}

/// What one sudoers file says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SudoersScan {
    pub(super) rules: Vec<RuleLine>,
    pub(super) includes: Vec<Include>,
    /// Every `secure_path` value, as written.
    pub(super) secure_paths: Vec<Vec<u8>>,
    /// Physical lines (from 1) whose reading depends on lexer behaviour this
    /// module does not model; see [`read_line`].
    pub(super) unmodelled: Vec<usize>,
}

/// Alias definitions, which cannot carry a tag and grant nothing by
/// themselves.
const ALIAS_KEYWORDS: [&[u8]; 5] = [
    b"User_Alias",
    b"Runas_Alias",
    b"Host_Alias",
    b"Cmnd_Alias",
    b"Cmd_Alias",
];

/// Reads one sudoers file.
pub(super) fn scan_sudoers(bytes: &[u8]) -> SudoersScan {
    let mut scan = SudoersScan::default();
    let read = logical_lines(bytes, is_sudoers_comment, Dialect::Sudo);
    scan.unmodelled = read.unmodelled;
    for Logical {
        line,
        text: body,
        glued,
        later,
        whole,
        uncertain,
    } in read.logical
    {
        let statement = body.trim_ascii_start();
        // Every file or directory this logical line may name. An include on a
        // line a continuation may have joined to the next one is still
        // followed, but what the rest of the joined line says is read too: the
        // next line may be a rule the include's path absorbed.
        let mut named: Vec<Include> = include_directive(statement).into_iter().collect();
        let settled_include = !named.is_empty();
        if uncertain {
            // A line after the first may not have been joined to it (sudo
            // reads `lecture_file=/etc/x\ ` as ending in an escaped blank, and
            // a comment eats a backslash): an include that starts one is a
            // directive of its own, whatever the program made of the join, and
            // the file it names is read.
            //
            // And an include path is the one token that keeps a trailing
            // backslash: sudo reads `@include /p\` as the path `/p\`, never as
            // `/p` and a continuation (its lexer's include token takes
            // everything up to a blank, and a final backslash is literal). So
            // each physical line is read twice, with its backslash cut off, as
            // a continuation, and whole, as the path; a path that is not
            // there is reported as unverified, so reading both only adds to
            // what is reported.
            //
            // The candidates are hints, not necessarily the file the program
            // opens: a quoted continuation or a path that starts on a
            // continuation line reaches files none of them name. So a line
            // that names an include at all is reported as one (below), and
            // plan item D3, the oracle that asks sudo itself, is what will
            // replace that finding with an answer.
            for physical in later.iter().chain(&whole) {
                let found = include_directive(physical.trim_ascii_start());
                if let Some(found) = found.filter(|found| !named.contains(found)) {
                    named.push(found);
                }
            }
            // The word `include` anywhere in the joined text, in a physical
            // line or across a join (`@incl\` + `ude`), is enough (every
            // include named above has it): more is reported than the
            // program reads, never less. It is reported on the physical line
            // that holds the word, or on the first when the join makes it.
            if contains(&glued, b"include") {
                let at = whole
                    .iter()
                    .position(|physical| contains(physical, b"include"));
                scan.rules.push(RuleLine {
                    line: line.saturating_add(at.unwrap_or(0)),
                    text: body.clone(),
                    grant: Grant::Include,
                    scope: Scope::Unknown,
                });
            }
            // Whatever kind of statement this was taken for, the lexer may
            // have read it as another: a tag anywhere in it is a rule that
            // names someone this cannot resolve.
            if let Some(rest) = word_at_start(statement, b"Defaults") {
                scan.secure_paths.extend(secure_path_value(rest));
            }
            let grants = [
                (contains(&glued, b"NOPASSWD"), Grant::Nopasswd),
                (
                    disables_authentication(statement) || disables_authentication(&glued),
                    Grant::NoAuthenticate,
                ),
            ];
            for (present, grant) in grants {
                if present {
                    scan.rules.push(RuleLine {
                        line,
                        text: body.clone(),
                        grant,
                        scope: Scope::Unknown,
                    });
                }
            }
        } else if settled_include {
            // Nothing else on an include line.
        } else if let Some(rest) = word_at_start(statement, b"Defaults") {
            let blanked = rest.trim_ascii_start();
            let scope = match (rest.first(), blanked.first()) {
                // `Defaults!cmnd`, with no blank between.
                (Some(b'!'), _) | (_, Some(b'@' | b'>')) => Scope::Unknown,
                (_, Some(b':')) => users_scope(blanked.get(1..).unwrap_or_default()),
                _ => Scope::Everyone,
            };
            if disables_authentication(rest) {
                scan.rules.push(RuleLine {
                    line,
                    text: body.clone(),
                    grant: Grant::NoAuthenticate,
                    scope,
                });
            }
            scan.secure_paths.extend(secure_path_value(rest));
        } else if !is_alias_definition(statement) {
            if after_word(statement, b"NOPASSWD").is_some() {
                scan.rules.push(RuleLine {
                    line,
                    text: body.clone(),
                    grant: Grant::Nopasswd,
                    scope: users_scope(statement),
                });
            }
            // Not a place `!authenticate` belongs, and so not one whose
            // meaning can be read: said, as "maybe", rather than passed over.
            if disables_authentication(statement) {
                scan.rules.push(RuleLine {
                    line,
                    text: body,
                    grant: Grant::NoAuthenticate,
                    scope: Scope::Unknown,
                });
            }
        }
        scan.includes.extend(named);
    }
    scan
}

/// Reads one doas configuration file: every `permit` rule carrying `nopass`.
pub(super) fn scan_doas(bytes: &[u8]) -> Vec<RuleLine> {
    logical_lines(bytes, is_hash_comment, Dialect::Doas)
        .logical
        .into_iter()
        .filter_map(|logical| {
            let scope = if logical.uncertain {
                // Whatever this line is the start of, `nopass` anywhere in it,
                // even across a join, may be a rule: `permit nopass 10\` and
                // `00` is uid 1000 to `OpenDoas`, and so is `nopas\s` the
                // keyword, because `OpenDoas` drops the backslash of an escape.
                spelled_with_or_without_escapes(&logical.glued, b"nopass")
                    .then_some(Scope::Unknown)?
            } else {
                let rest = word_at_start(logical.text.trim_ascii_start(), b"permit")?;
                after_word(rest, b"nopass")?;
                doas_scope(rest)
            };
            Some(RuleLine {
                line: logical.line,
                text: logical.text,
                grant: Grant::Nopass,
                scope,
            })
        })
        .collect()
}

/// The physical lines (from 1) of a doas file whose reading depends on lexer
/// behaviour this module does not model.
pub(super) fn doas_unmodelled(bytes: &[u8]) -> Vec<usize> {
    logical_lines(bytes, is_hash_comment, Dialect::Doas).unmodelled
}

/// Whether a statement defines an alias. An alias names things and cannot
/// carry a tag; only a user specification grants anything.
fn is_alias_definition(statement: &[u8]) -> bool {
    ALIAS_KEYWORDS
        .iter()
        .any(|keyword| word_at_start(statement, keyword).is_some())
}

/// Resolves an include directive's path the way sudo does: relative to the
/// directory of the file that names it, `%%` meaning `%`.
///
/// `None` for a path naming the host (`%h`), which this does not expand: the
/// caller reports it as unverified rather than guessing.
pub(super) fn resolve_include(from: &Path, raw: &[u8]) -> Option<PathBuf> {
    let mut path = Vec::with_capacity(raw.len());
    let mut bytes = raw.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            path.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'h') => return None,
            Some(b'%') | None => path.push(b'%'),
            Some(other) => path.extend([b'%', other]),
        }
    }
    let path = PathBuf::from(OsString::from_vec(path));
    if path.is_absolute() {
        return Some(path);
    }
    Some(from.parent().unwrap_or(Path::new("/")).join(path))
}

/// A decimal id, or `None` for anything else: an empty string, a sign (which
/// `str::parse` would accept), or a value too large for an id.
pub(super) fn number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit <= 9)?;
        value.checked_mul(10)?.checked_add(u32::from(digit))
    })
}

/// Whether a user-list item is an alias name: `[A-Z][A-Z0-9_]*`.
pub(super) fn is_alias(item: &[u8]) -> bool {
    item.first().is_some_and(u8::is_ascii_uppercase)
        && item
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Which program's lexer reads a file. They differ in what a physical line is
/// (sudo ends one at `\r\n`, `OpenDoas` reads the `\r` as a byte) and in whether
/// `#<digit>` is an id and not a comment (sudo's rule, not `OpenDoas`'s). They
/// no longer differ in where a line continues: every trailing backslash is
/// unmodelled in both.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// sudo's `toke.l`.
    Sudo,
    /// `OpenDoas`'s `yylex`.
    Doas,
}

/// One logical line of a file.
struct Logical {
    /// Its first physical line, counting from 1.
    line: usize,
    /// Its physical lines joined with a space.
    text: Vec<u8>,
    /// The same, joined with nothing: where a word may be split across a join.
    glued: Vec<u8>,
    /// Each physical line after the first, on its own: the program may not have
    /// joined it (a comment can eat the backslash, an escaped blank is not a
    /// continuation), so it may be a directive of its own.
    later: Vec<Vec<u8>>,
    /// Every physical line, the first included, on its own and whole: past a
    /// carriage return, but with its trailing backslash and blanks still on it,
    /// where `later` has them cut off. sudo reads an include path with a final
    /// backslash in it, so an include on a line that ends in one names the file
    /// with that backslash as well.
    whole: Vec<Vec<u8>>,
    /// Whether any physical line in it ends in a backslash or is otherwise
    /// [unmodelled](read_line), so that what it joined is a guess.
    uncertain: bool,
}

/// A file's lines as the program would read them.
struct Lines {
    /// Continuation lines joined, whole-line comments dropped: each with the
    /// number of its first physical line, and whether any physical line in it
    /// is [unmodelled](read_line), so that what it joined is a guess.
    logical: Vec<Logical>,
    /// Every physical line (from 1) that is unmodelled and not a whole-line
    /// comment.
    unmodelled: Vec<usize>,
}

/// The lines of a file, continuation lines joined, whole-line comments
/// dropped, each with the number of its first physical line.
fn logical_lines(bytes: &[u8], is_comment: fn(&[u8]) -> bool, dialect: Dialect) -> Lines {
    let mut lines = Vec::new();
    let mut unmodelled = Vec::new();
    let mut pending: Option<Logical> = None;
    // Whether the previous physical line was a whole-line comment that ends in
    // a backslash: what it joins to is not known, so the next line is not
    // either.
    let mut after_comment_continuation = false;
    for (index, raw) in bytes.split(|byte| *byte == b'\n').enumerate() {
        // sudo reads `\r\n` as a line end; OpenDoas reads the `\r` as a byte.
        let line = match dialect {
            Dialect::Sudo => raw.strip_suffix(b"\r").unwrap_or(raw),
            Dialect::Doas => raw,
        };
        let reading = read_line(raw, dialect);
        let body = line.get(..reading.cut).unwrap_or(line);
        let number = index.saturating_add(1);
        let tainted = std::mem::take(&mut after_comment_continuation);
        let current = match pending.take() {
            Some(mut joined) => {
                joined.text.push(b' ');
                joined.text.extend_from_slice(body);
                joined.glued.extend_from_slice(body);
                joined.later.push(body.to_vec());
                joined.whole.push(line.to_vec());
                joined.uncertain |= !reading.modelled;
                joined
            }
            None if is_comment(line) => {
                if reading.continues {
                    unmodelled.push(number);
                    after_comment_continuation = true;
                }
                continue;
            }
            None => Logical {
                line: number,
                text: body.to_vec(),
                glued: body.to_vec(),
                later: Vec::new(),
                whole: vec![line.to_vec()],
                uncertain: tainted || !reading.modelled,
            },
        };
        if !reading.modelled {
            unmodelled.push(number);
        }
        if reading.continues {
            pending = Some(current);
        } else {
            lines.push(current);
        }
    }
    lines.extend(pending);
    Lines {
        logical: lines,
        unmodelled,
    }
}

/// How one physical line reads.
struct Reading {
    /// Where the line's text ends: before a trailing backslash, else the whole
    /// line.
    cut: usize,
    /// Whether the line ends in a backslash, and so may continue onto the next.
    continues: bool,
    /// Whether every construct on it is one this module models and tests. A
    /// line that ends in a backslash never is.
    modelled: bool,
}

/// Reads one physical line left to right, with escape semantics.
///
/// **A line that ends in a backslash is never modelled.** Whether sudo or
/// `OpenDoas` joins it to the next line depends on what precedes the
/// backslash (an escape, a comment, a quote, a token under way, a carriage
/// return), and four rounds of review each found another case where this
/// module and the real lexer disagreed. So the line counts as ending in a
/// backslash when its last byte, past trailing whitespace, is one, whatever
/// precedes it and in either dialect: the line it may join is
/// [unmodelled](Reading::modelled), and everything it could form is
/// unresolved.
///
/// Within a line that does not, a backslash escapes the next byte, so `\\` is
/// a literal backslash and `\#` is not a comment. A `#` starts a comment that
/// swallows the rest of the line, wherever it stands and blank before it or
/// not; in sudo a `#<digit>` or `#-<digit>` is a user or group id and not a
/// comment, and `OpenDoas` has no such exception.
///
/// Only these escapes are modelled, each with a test: `\\`, `\#`, and a
/// backslash and a blank. Anything else leaves the line **unmodelled**: a
/// backslash before any other byte (sudo and `OpenDoas` both give those
/// meanings, `\xHH` among them, that this does not reproduce), and a double
/// quote on a line that also has a backslash or a `#` other than the first byte
/// on it (inside quotes both lexers read those differently). A rule the
/// program may or may not join with an unmodelled line is reported as applying
/// to someone aido cannot resolve, and the file is listed as unverified, so its
/// check is never clean.
fn read_line(line: &[u8], dialect: Dialect) -> Reading {
    let significant = line.trim_ascii_end();
    let continues = significant.last() == Some(&b'\\');
    let cut = if continues {
        significant.len().saturating_sub(1)
    } else {
        line.len()
    };
    let mut at = 0_usize;
    let mut modelled = !continues;
    let (mut quoted, mut escaped, mut hashed) = (false, false, false);
    while let Some(byte) = line.get(at) {
        let rest = line.get(at.saturating_add(1)..).unwrap_or_default();
        match byte {
            b'\\' => {
                escaped = true;
                modelled &= matches!(rest.first(), Some(b'\\' | b'#' | b' ' | b'\t'));
                at = at.saturating_add(1);
            }
            b'#' => {
                hashed |= !trim_blanks_end(line.get(..at).unwrap_or_default()).is_empty();
                if dialect == Dialect::Doas || !starts_id(rest) {
                    break;
                }
            }
            b'"' => quoted = true,
            _ => {}
        }
        at = at.saturating_add(1);
    }
    Reading {
        cut,
        continues,
        modelled: modelled && !(quoted && (escaped || hashed)),
    }
}

/// Whether what follows a `#` makes it a user or group id (`#1000`, `#-1`)
/// and not a comment: sudo's comment rule excludes `#<digit>` and
/// `#-<digit>`.
fn starts_id(after_hash: &[u8]) -> bool {
    match after_hash {
        [digit, ..] if digit.is_ascii_digit() => true,
        [b'-', digit, ..] => digit.is_ascii_digit(),
        _ => false,
    }
}

/// A space or a tab: sudo's `[[:blank:]]`.
fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// A line's trailing spaces and tabs, removed.
fn trim_blanks_end(line: &[u8]) -> &[u8] {
    let kept = line
        .iter()
        .rposition(|byte| !is_blank(*byte))
        .map_or(0, |last| last.saturating_add(1));
    line.get(..kept).unwrap_or_default()
}

/// Whether a sudoers line is a comment: `#` first, but not an include and not
/// a `#<uid>` user specification.
fn is_sudoers_comment(line: &[u8]) -> bool {
    match line.trim_ascii_start() {
        [b'#', rest @ ..] if starts_id(rest) => false,
        text @ [b'#', ..] => include_directive(text).is_none(),
        _ => false,
    }
}

/// Whether a doas line is a comment.
fn is_hash_comment(line: &[u8]) -> bool {
    line.trim_ascii_start().first() == Some(&b'#')
}

/// An include directive, if this statement is one.
fn include_directive(statement: &[u8]) -> Option<Include> {
    const DIRECTIVES: [(&[u8], bool); 4] = [
        (b"#includedir", true),
        (b"@includedir", true),
        (b"#include", false),
        (b"@include", false),
    ];
    DIRECTIVES.iter().find_map(|(directive, is_dir)| {
        let path = include_path(word_at_start(statement, directive)?.trim_ascii_start());
        if path.is_empty() {
            return None;
        }
        Some(if *is_dir {
            Include::Dir(path)
        } else {
            Include::File(path)
        })
    })
}

/// An include's path as sudo reads it: up to the first blank that is not
/// escaped, or between double quotes. A backslash makes the next byte literal
/// (`\ ` is a space in the name), and `\xHH` is the byte `HH`.
fn include_path(text: &[u8]) -> Vec<u8> {
    let (mut rest, quoted) = text
        .strip_prefix(b"\"")
        .map_or((text, false), |inside| (inside, true));
    let mut path = Vec::new();
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if (quoted && byte == b'"') || (!quoted && is_blank(byte)) {
            break;
        }
        if byte != b'\\' {
            path.push(byte);
            continue;
        }
        match escaped_byte(rest) {
            Some((decoded, after)) => {
                path.push(decoded);
                rest = after;
            }
            // A backslash with nothing after it is just a backslash.
            None => path.push(byte),
        }
    }
    path
}

/// The byte a backslash escape stands for, and what follows it: `xHH` is a
/// hexadecimal byte, anything else stands for itself.
fn escaped_byte(after_backslash: &[u8]) -> Option<(u8, &[u8])> {
    let hex = |digit: &u8| {
        char::from(*digit)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    if let [b'x', high, low, tail @ ..] = after_backslash {
        if let (Some(high), Some(low)) = (hex(high), hex(low)) {
            return Some((high.saturating_mul(16).saturating_add(low), tail));
        }
    }
    after_backslash
        .split_first()
        .map(|(byte, tail)| (*byte, tail))
}

/// A sudoers user list, or [`Scope::Unknown`] when nothing can be read from
/// it.
fn users_scope(text: &[u8]) -> Scope {
    let mut items = Vec::new();
    let mut rest = text.trim_ascii_start();
    loop {
        let (item, after) = take_item(rest);
        if item.is_empty() {
            break;
        }
        items.push(item);
        match after.trim_ascii_start().strip_prefix(b",") {
            Some(next) => rest = next.trim_ascii_start(),
            None => break,
        }
    }
    if items.is_empty() {
        Scope::Unknown
    } else {
        Scope::Users(items)
    }
}

/// A doas rule's identity: the first token after its options.
fn doas_scope(rest: &[u8]) -> Scope {
    let mut tokens = rest
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        match token {
            b"nopass" | b"nolog" | b"persist" | b"keepenv" => {}
            b"setenv" => {
                // `setenv { ... }`: skip through the closing brace.
                if !tokens.by_ref().any(|token| token.ends_with(b"}")) {
                    return Scope::Unknown;
                }
            }
            identity => {
                // A quoted identity is the same identity.
                let unquoted = identity.iter().copied().filter(|byte| *byte != b'"');
                return Scope::DoasIdentity(unquoted.collect());
            }
        }
    }
    Scope::Unknown
}

/// Whether a `Defaults` line turns authentication off.
fn disables_authentication(text: &[u8]) -> bool {
    let mut rest = text;
    while let Some(at) = rest.iter().position(|byte| *byte == b'!') {
        rest = rest.get(at.saturating_add(1)..).unwrap_or_default();
        if word_at_start(rest.trim_ascii_start(), b"authenticate").is_some() {
            return true;
        }
    }
    false
}

/// The value of a `secure_path` setting on a `Defaults` line.
fn secure_path_value(text: &[u8]) -> Option<Vec<u8>> {
    let value = after_word(text, b"secure_path")?
        .trim_ascii_start()
        .strip_prefix(b"=")?;
    Some(take_item(value.trim_ascii_start()).0)
}

/// One item: a quoted string without its quotes, or a run of bytes up to
/// whitespace or a comma. Returns the item and what follows it.
fn take_item(text: &[u8]) -> (Vec<u8>, &[u8]) {
    if let Some(quoted) = text.strip_prefix(b"\"") {
        let end = quoted
            .iter()
            .position(|byte| *byte == b'"')
            .unwrap_or(quoted.len());
        let (item, after) = quoted.split_at_checked(end).unwrap_or((quoted, &[]));
        return (item.to_vec(), after.get(1..).unwrap_or_default());
    }
    let end = text
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || *byte == b',')
        .unwrap_or(text.len());
    let (item, after) = text.split_at_checked(end).unwrap_or((text, &[]));
    (item.to_vec(), after)
}

/// Whether `needle` occurs in `text` at all: no word boundaries, because a word
/// split across a join has none where it was split.
fn contains(text: &[u8], needle: &[u8]) -> bool {
    text.windows(needle.len()).any(|window| window == needle)
}

/// Whether `needle` occurs in `text` as written, or once every backslash is
/// removed: `OpenDoas` drops the backslash of an escape (`nopas\s` is the
/// keyword `nopass`; run through `OpenDoas` 6.8.2 it grants), and a line that
/// holds an escape this module does not model is one it cannot read word by
/// word. More than the program reads is reported, never less.
fn spelled_with_or_without_escapes(text: &[u8], needle: &[u8]) -> bool {
    let unescaped: Vec<u8> = text.iter().copied().filter(|byte| *byte != b'\\').collect();
    contains(text, needle) || contains(&unescaped, needle)
}

/// What follows `word` at the start of `text`, if it starts with `word` as a
/// whole word.
fn word_at_start<'a>(text: &'a [u8], word: &[u8]) -> Option<&'a [u8]> {
    let rest = text.strip_prefix(word)?;
    if rest.first().copied().is_some_and(is_word_byte) {
        None
    } else {
        Some(rest)
    }
}

/// What follows the first whole-word occurrence of `word` in `text`.
fn after_word<'a>(text: &'a [u8], word: &[u8]) -> Option<&'a [u8]> {
    let mut before: Option<u8> = None;
    let mut rest = text;
    while let Some((first, tail)) = rest.split_first() {
        if !before.is_some_and(is_word_byte) {
            if let Some(after) = word_at_start(rest, word) {
                return Some(after);
            }
        }
        before = Some(*first);
        rest = tail;
    }
    None
}

/// A byte that continues a word.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every line ending in a backslash the property tests try: any preceding
/// bytes (rules, comments, quotes, `#`, escapes, an escaped backslash, a lone
/// blank), blanks and a carriage return before and after the backslash.
#[cfg(test)]
pub(super) fn lines_ending_in_a_backslash() -> Vec<Vec<u8>> {
    let prefixes: [&[u8]; 18] = [
        b"",
        b"alice ALL=(ALL) ALL",
        b"alice ALL=(ALL) NOPASSWD: ALL",
        b"Defaults:alice lecture_file=/etc/x",
        b"Cmnd_Alias X = /bin/true",
        b"permit alice cmd /bin/ls",
        b"permit nopass alice",
        b"a#b",
        b"#x",
        b"# a comment",
        b"\"q",
        b"x\\\\",
        b"x\\",
        b"a\\q",
        b"a\\#b",
        b"a #1000",
        b"@include /etc/sudoers.d/x",
        b"%$#",
    ];
    let blanks: [&[u8]; 4] = [b"", b" ", b"\t", b" \t "];
    let afters: [&[u8]; 4] = [b"", b" ", b"\t", b"\r"];
    let ends: [&[u8]; 2] = [b"\n", b"\r\n"];
    let mut lines = Vec::new();
    for prefix in prefixes {
        for before in blanks {
            for after in afters {
                for end in ends {
                    let mut line = prefix.to_vec();
                    line.extend_from_slice(before);
                    line.push(b'\\');
                    line.extend_from_slice(after);
                    line.extend_from_slice(end);
                    lines.push(line);
                }
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// A line without its continuation marker, and whether it had one.
    fn continuation(line: &[u8], dialect: Dialect) -> (&[u8], bool) {
        let reading = read_line(line, dialect);
        (&line[..reading.cut], reading.continues)
    }

    fn users(items: &[&str]) -> Scope {
        Scope::Users(items.iter().map(|i| i.as_bytes().to_vec()).collect())
    }

    #[test]
    fn a_nopasswd_rule_is_found_with_its_line_and_user_list() {
        let scan = scan_sudoers(
            b"# a header\n\
              Defaults env_reset\n\
              root ALL=(ALL:ALL) ALL\n\
              %sudo, alice  ALL=(ALL) NOPASSWD: /usr/bin/apt\n",
        );
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 4);
        assert_eq!(scan.rules[0].grant, Grant::Nopasswd);
        assert_eq!(scan.rules[0].scope, users(&["%sudo", "alice"]));
        assert!(scan.includes.is_empty());
        assert!(format!("{:?}", scan.clone()).contains("Nopasswd"));
    }

    #[test]
    fn a_commented_out_rule_is_not_a_rule_but_a_uid_user_is() {
        // Fedora ships `# %wheel ALL=(ALL) NOPASSWD: ALL` commented out on
        // every host; reporting it would bury the real finding in noise.
        // `#1000` is a uid, not a comment.
        let scan = scan_sudoers(
            b"# %wheel ALL=(ALL) NOPASSWD: ALL\n\
              \t#1000 ALL=(ALL) NOPASSWD: ALL\n",
        );
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 2);
        assert_eq!(scan.rules[0].scope, users(&["#1000"]));
    }

    #[test]
    fn denies_hiding_nopasswd_on_a_continuation_line() {
        // The tag on the second physical line still belongs to the rule on
        // the first, and the rule is reported at the line it starts on.
        let scan = scan_sudoers(b"alice ALL=(ALL) \\\n  NOPASSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 1);
        assert_eq!(
            scan.rules[0].text,
            b"alice ALL=(ALL)    NOPASSWD: ALL".to_vec()
        );
    }

    #[test]
    fn denies_hiding_a_live_rule_behind_a_commented_continuation() {
        // A comment line ending in a backslash does not swallow the next line,
        // but nobody can say what it joins: the rule is found, as "maybe"
        // (it was `bob` before the decision to stop modelling continuations).
        let scan = scan_sudoers(b"# old rule \\\nbob ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 2);
        assert_eq!(scan.rules[0].scope, Scope::Unknown);
        assert_eq!(scan.unmodelled, vec![1]);
    }

    #[test]
    fn a_file_ending_mid_continuation_still_reports_the_rule() {
        let scan = scan_sudoers(b"carol ALL=(ALL) NOPASSWD: ALL \\");
        assert_eq!(scan.rules.len(), 1);
    }

    #[test]
    fn denies_a_trailing_comment_hiding_the_tag() {
        // A `#` after the tag does not end the line before it is seen, and a
        // `#` before it does not end the line either: the rule is reported.
        for text in [
            &b"dave ALL=(ALL) NOPASSWD: ALL # fine\n"[..],
            &b"erin ALL = /bin/x#y, NOPASSWD: /bin/z\n"[..],
        ] {
            assert_eq!(scan_sudoers(text).rules.len(), 1, "{text:?}");
        }
    }

    #[test]
    fn nopasswd_must_be_a_whole_word() {
        // Inside an alias name or a path it is not the tag; aliases are never
        // grants; on a Defaults line it cannot be a tag either.
        let scan = scan_sudoers(
            b"Cmnd_Alias MY_NOPASSWD_CMDS = /bin/true\n\
              alice ALL = /opt/NOPASSWDtool\n\
              Defaults lecturefile=/etc/NOPASSWD\n\
              alice ALL = /opt/x_NOPASSWD\n",
        );
        assert!(scan.rules.is_empty(), "{:?}", scan.rules);
    }

    #[test]
    fn authenticate_off_is_a_passwordless_grant_with_its_scope() {
        let scan = scan_sudoers(
            b"Defaults !authenticate\n\
              Defaults:bob ! authenticate\n\
              Defaults!/usr/bin/apt !authenticate\n\
              Defaults@host1 !authenticate\n\
              Defaults>root !authenticate\n\
              Defaults:%admin,bob !authenticate\n\
              Defaults authenticate\n\
              Defaults !authenticated_thing, !lecture\n",
        );
        let scopes: Vec<Scope> = scan.rules.iter().map(|r| r.scope.clone()).collect();
        assert_eq!(
            scopes,
            vec![
                Scope::Everyone,
                users(&["bob"]),
                Scope::Unknown,
                Scope::Unknown,
                Scope::Unknown,
                users(&["%admin", "bob"]),
            ]
        );
        assert!(scan.rules.iter().all(|r| r.grant == Grant::NoAuthenticate));
    }

    #[test]
    fn includes_are_collected_in_every_spelling() {
        let scan = scan_sudoers(
            b"#includedir /etc/sudoers.d\n\
              @includedir \"/etc/with space.d\"\n\
              #include /etc/sudoers.local\n\
              @include relative.conf\n\
              #include\n\
              #includefoo /x\n",
        );
        assert_eq!(
            scan.includes,
            vec![
                Include::Dir(b"/etc/sudoers.d".to_vec()),
                Include::Dir(b"/etc/with space.d".to_vec()),
                Include::File(b"/etc/sudoers.local".to_vec()),
                Include::File(b"relative.conf".to_vec()),
            ]
        );
        assert!(scan.rules.is_empty());
    }

    #[test]
    fn secure_path_is_read_quoted_or_bare() {
        let scan = scan_sudoers(
            b"Defaults secure_path=\"/usr/sbin:/usr/bin\"\n\
              Defaults secure_path = /opt/bin:/bin, env_reset\n\
              Defaults secure_path\n\
              Defaults secure_path=\"/unterminated\n",
        );
        assert_eq!(
            scan.secure_paths,
            vec![
                b"/usr/sbin:/usr/bin".to_vec(),
                b"/opt/bin:/bin".to_vec(),
                b"/unterminated".to_vec(),
            ]
        );
    }

    #[test]
    fn an_unreadable_user_list_is_unknown_rather_than_nobody() {
        assert_eq!(users_scope(b""), Scope::Unknown);
        assert_eq!(users_scope(b"  "), Scope::Unknown);
        assert_eq!(users_scope(b"\"quoted user\" ALL"), users(&["quoted user"]));
        assert_eq!(users_scope(b"a ,b, c ALL"), users(&["a", "b", "c"]));
        assert_eq!(users_scope(b"a,"), users(&["a"]));
    }

    #[test]
    fn doas_nopass_rules_are_found_with_their_identity() {
        let rules = scan_doas(
            b"# permit nopass :wheel\n\
              permit persist :wheel\n\
              permit nopass keepenv setenv { PATH=/x HOME } :admin as root\n\
              permit nolog nopass alice cmd /bin/true\n\
              deny nopass bob\n\
              permit nopass\n\
              permit nopass setenv { NEVER_CLOSED\n\
              permit nopass setenv {A=1} 1000 \\\n  cmd x\n\
              permitted nopass alice\n",
        );
        let scopes: Vec<Scope> = rules.iter().map(|r| r.scope.clone()).collect();
        assert_eq!(
            scopes,
            vec![
                Scope::DoasIdentity(b":admin".to_vec()),
                Scope::DoasIdentity(b"alice".to_vec()),
                Scope::Unknown,
                Scope::Unknown,
                // Ends in a backslash: not modelled, so not `1000`.
                Scope::Unknown,
            ]
        );
        assert_eq!(rules[0].line, 3);
        assert!(rules.iter().all(|r| r.grant == Grant::Nopass));
    }

    #[test]
    fn an_include_resolves_like_sudo_resolves_it() {
        let from = Path::new("/etc/sudoers.d/10-local");
        assert_eq!(
            resolve_include(from, b"/etc/x"),
            Some(PathBuf::from("/etc/x"))
        );
        assert_eq!(
            resolve_include(from, b"extra"),
            Some(PathBuf::from("/etc/sudoers.d/extra"))
        );
        assert_eq!(
            resolve_include(from, b"/etc/100%%-%x%"),
            Some(PathBuf::from("/etc/100%-%x%"))
        );
        assert_eq!(resolve_include(from, b"/etc/sudoers.%h"), None);
        assert_eq!(
            resolve_include(Path::new(""), b"bare"),
            Some(PathBuf::from("/bare"))
        );
    }

    #[test]
    fn ids_are_decimal_digits_and_nothing_else() {
        assert_eq!(number(b"1000"), Some(1000));
        assert_eq!(number(b"0"), Some(0));
        assert_eq!(number(b""), None);
        assert_eq!(number(b"+5"), None);
        assert_eq!(number(b"5a"), None);
        assert_eq!(number(b"5/"), None);
        assert_eq!(number(b"4294967295"), Some(u32::MAX));
        // One past the largest id, overflowing on the last digit and on the
        // one before it.
        assert_eq!(number(b"4294967296"), None);
        assert_eq!(number(b"99999999999"), None);
        assert!(is_alias(b"ADMINS_2"));
        assert!(!is_alias(b"Admins"));
        assert!(!is_alias(b"_X"));
        assert!(!is_alias(b""));
    }

    #[test]
    fn words_are_bounded_on_both_sides() {
        assert_eq!(after_word(b"x NOPASSWD: y", b"NOPASSWD"), Some(&b": y"[..]));
        assert_eq!(after_word(b"xNOPASSWD", b"NOPASSWD"), None);
        assert_eq!(after_word(b"NOPASSWDx", b"NOPASSWD"), None);
        assert_eq!(after_word(b"", b"NOPASSWD"), None);
        assert_eq!(word_at_start(b"permitted", b"permit"), None);
        assert_eq!(word_at_start(b"permit x", b"permit"), Some(&b" x"[..]));
        assert_eq!(take_item(b"\"open"), (b"open".to_vec(), &b""[..]));
        assert!(format!("{:?}", Include::File(Vec::new()).clone()).contains("File"));
        assert!(format!("{:?}", Grant::Nopass).contains("Nopass"));
    }

    #[test]
    fn a_sudo_line_ending_in_a_backslash_may_continue_whatever_precedes_it() {
        // Every line whose last byte, past trailing whitespace, is a backslash
        // may join the next, in the lexer or not; none is modelled further.
        for (line, joined) in [
            (&b"a \\"[..], true),
            (b"a \\ \t ", true),
            (b"a \\ x", false),
            (b"a # c \\", true),
            (b"# c \\", true),
            (b"a #1000 \\", true),
            (b"a#1000 \\", true),
            (b"a#b \\", true),
            (b"a\\", true),
            (b"a \\\r", true),
            (b"", false),
            (b"   ", false),
        ] {
            assert_eq!(continuation(line, Dialect::Sudo).1, joined, "{line:?}");
            assert_eq!(read_line(line, Dialect::Sudo).modelled, !joined, "{line:?}");
        }
        assert_eq!(continuation(b"a \\ ", Dialect::Sudo).0, b"a ");
        assert_eq!(continuation(b"a # b \\", Dialect::Sudo).0, b"a # b ");
        assert_eq!(trim_blanks_end(b" \t "), b"");
    }

    #[test]
    fn a_doas_line_ending_in_a_backslash_may_continue_whatever_precedes_it() {
        // OpenDoas joins only a backslash before the newline, but a backslash
        // and a blank, or a `#` before it, are not modelled either way.
        for (line, joined) in [
            (&b"a \\"[..], true),
            (b"a \\ ", true),
            (b"a \\\t", true),
            (b"a \\\r", true),
            (b"a #1000 \\", true),
            (b"a#b \\", true),
            (b"a # b \\", true),
            (b"", false),
        ] {
            assert_eq!(continuation(line, Dialect::Doas).1, joined, "{line:?}");
        }
        assert_eq!(continuation(b"a \\ ", Dialect::Doas).0, b"a ");
    }

    #[test]
    fn denies_a_hash_without_a_blank_swallowing_the_backslash_to_hide_a_rule_under_an_alias() {
        // sudo 1.9.16p2: `visudo -c` parses each of these and `sudo -n true`
        // as the caller succeeds, because the comment ends the line and the
        // rule below it stands alone.
        for head in [
            &b"Cmnd_Alias X = /bin/true#c \\\n"[..],
            b"Defaults:alice lecture_file=/etc/x#c \\\n",
            b"alice ALL=(ALL) ALL#x \\\n",
            b"alice ALL=(ALL) /bin/true#x \\\n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            // The rule below is found on the logical line that starts at the
            // head, as "maybe": it was `yamin` before continuations stopped
            // being modelled, and never `alice`'s or lost.
            assert_eq!(scan.rules.len(), 1, "{head:?}");
            assert_eq!(scan.rules[0].line, 1, "{head:?}");
            assert_eq!(scan.rules[0].scope, Scope::Unknown, "{head:?}");
            assert_eq!(scan.unmodelled, vec![1], "{head:?}");
        }
    }

    #[test]
    fn denies_an_escaped_blank_or_a_midword_hash_hiding_a_doas_rule_below() {
        // OpenDoas: `permit alice cmd /bin/ls args \ ` ends the rule at the
        // escaped blank, and `/bin/ls#x \` ends it at the `#`. `doas -n true`
        // as the caller then succeeds on the `permit nopass` line below.
        for head in [
            &b"permit alice cmd /bin/ls args \\ \n"[..],
            b"permit alice cmd /bin/ls#x \\\n",
            b"permit alice cmd /bin/ls args \\\r\n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(b"permit nopass yamin\n");
            let rules = scan_doas(&text);
            // Found as "maybe" (it was `yamin` before continuations stopped
            // being modelled).
            assert_eq!(rules.len(), 1, "{head:?}");
            assert_eq!(rules[0].line, 1, "{head:?}");
            assert_eq!(rules[0].scope, Scope::Unknown, "{head:?}");
            assert_eq!(doas_unmodelled(&text), vec![1], "{head:?}");
        }
    }

    #[test]
    fn denies_an_escaped_backslash_at_the_end_of_a_line_absorbing_the_callers_rule() {
        // sudo 1.9.16p2: `\\` then the newline is a literal backslash, and the
        // rule on the next line is its own. Joined, it vanished under a
        // `Defaults` or alias line (never read for a tag: cases L, M, P) or
        // under alice's rule (case N).
        for head in [
            &b"Defaults:alice lecture_file=/etc/x\\\\\n"[..],
            b"Cmnd_Alias X = /bin/echo a\\\\\n",
            b"alice ALL=(ALL) /bin/echo a\\\\\n",
            b"Defaults:alice lecture_file=/etc/x\\\\ \n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            // "Maybe" (it was `yamin`, with nothing unmodelled, before
            // continuations stopped being modelled).
            assert_eq!(scan.rules.len(), 1, "{head:?}");
            assert_eq!(scan.rules[0].line, 1, "{head:?}");
            assert_eq!(scan.rules[0].scope, Scope::Unknown, "{head:?}");
            assert_eq!(scan.unmodelled, vec![1], "{head:?}");
        }
    }

    #[test]
    fn denies_an_escaped_backslash_at_the_end_of_a_doas_line_absorbing_the_callers_rule() {
        // OpenDoas: case R. `args a\\` then the newline ends the rule.
        let rules = scan_doas(b"permit alice cmd /bin/ls args a\\\\\npermit nopass yamin\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].line, 1);
        assert_eq!(rules[0].scope, Scope::Unknown);
        assert_eq!(
            doas_unmodelled(b"permit alice cmd /bin/ls args a\\\\\n"),
            vec![1]
        );
    }

    #[test]
    fn a_trailing_backslash_may_continue_whether_or_not_it_is_escaped() {
        for dialect in [Dialect::Sudo, Dialect::Doas] {
            for (line, joined) in [
                (&b"a \\\\"[..], true),
                (b"a \\\\\\", true),
                (b"a \\\\\\\\", true),
                (b"a \\# b \\", true),
                (b"a \\ \\", true),
            ] {
                assert_eq!(continuation(line, dialect).1, joined, "{line:?}");
            }
        }
        // An escaped `#` is not a comment, and a line ending in it ends in no
        // backslash.
        assert!(!continuation(b"a \\#", Dialect::Sudo).1);
        assert_eq!(continuation(b"a \\# \\", Dialect::Sudo).0, b"a \\# ");
    }

    #[test]
    fn denies_a_backslash_escaped_trailing_blank_absorbing_the_callers_rule() {
        // sudo 1.9.16p2: a backslash and blanks glued to a WORD, PATH or ENVAR
        // token are an escaped blank and the line ends; joined, the caller's
        // rule below vanished (T1, T2, T4, T5, T6, T7) or was credited to
        // alice (T3). Such a line is unmodelled, so what it joins is "maybe".
        for head in [
            &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
            b"Cmnd_Alias X = /bin/x\\ \n",
            b"alice ALL=(ALL) /bin/x\\ \n",
            b"Host_Alias H = foo\\ \n",
            b"Defaults:alice\\ \n",
            b"Defaults:alice lecture_file=/etc/x\\\t\n",
            b"Defaults:alice lecture_file=/etc/x\\\\\\ \n",
            b"alice ALL=(ALL) /bin/x\\ \r\n",
            b"alice ALL=(ALL) /bin/x\\\r\n",
            b"alice ALL=(ALL) /bin/x\\ \\ \n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            // Under an alias or `Defaults` head the joined line is never read
            // for a tag, so no rule is the point: the file is unverified.
            assert_eq!(scan.unmodelled, vec![1], "{head:?}");
            assert!(
                scan.rules.iter().all(|rule| rule.scope == Scope::Unknown),
                "{head:?}"
            );
        }
        // None is certain any more, after a blank or not.
        for line in [
            &b"a \\ "[..],
            b"a \\\t",
            b"\\ ",
            b"a\\",
            b"a \\\r",
            b"a\\ \\ ",
        ] {
            assert!(!read_line(line, Dialect::Sudo).modelled, "{line:?}");
        }
    }

    #[test]
    fn denies_a_negative_hash_id_hiding_a_continuation_as_another_users_rule() {
        // sudo's comment rule excludes `#-<digit>`: `#-1` is an id, the
        // backslash after it continues, and the next line is part of the
        // same rule. Read as a comment, the next line was credited to the
        // users it names (alice, bob).
        let scan = scan_sudoers(b"yamin ALL=(#-1,\\\nalice,bob ) NOPASSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 1);
        // "Maybe", since a line ending in a backslash is not modelled (it was
        // `yamin`).
        assert_eq!(scan.rules[0].scope, Scope::Unknown);
        for line in [&b"a #-1 \\"[..], b"a #1 \\", b"a #-x \\", b"a #- \\"] {
            assert!(read_line(line, Dialect::Sudo).continues, "{line:?}");
            assert!(read_line(line, Dialect::Doas).continues, "{line:?}");
        }
        // A line that starts with it is a user specification, not a comment.
        let scan = scan_sudoers(b"#-1 ALL=(ALL) NOPASSWD: ALL\n#-x ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].line, 1);
    }

    #[test]
    fn denies_an_escaped_hash_hiding_the_tag_behind_a_comment() {
        // `\#` is not a comment, so the tag after it is still on a live line.
        let scan = scan_sudoers(b"dave ALL=(ALL) /bin/a\\#b NOPASSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert!(scan.unmodelled.is_empty());
        assert_eq!(scan_doas(b"permit nopass dave cmd a\\#b\n").len(), 1);
    }

    #[test]
    fn an_unmodelled_construct_makes_what_it_could_join_unknown_never_clean() {
        // A backslash before any byte but the modelled ones, and a quote on a
        // line with a backslash or a non-leading `#`: the line is reported as
        // unmodelled, and a rule it was joined with names nobody aido can
        // resolve.
        for head in [
            &b"alice ALL=(ALL) /bin/echo \\q \\\n"[..],
            b"alice ALL=(ALL) /bin/echo \\x41 \\\n",
            b"alice ALL=(ALL) /bin/echo \"a\\\\\" \\\n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            assert_eq!(scan.unmodelled, vec![1], "{head:?}");
            assert_eq!(scan.rules.len(), 1, "{head:?}");
            assert_eq!(scan.rules[0].scope, Scope::Unknown, "{head:?}");
        }
        // A `#` inside quotes is a comment to us and may not be to sudo: the
        // line is flagged, and the file is reported unverified.
        assert_eq!(
            scan_sudoers(b"alice ALL = \"a#b\" \\\n").unmodelled,
            vec![1]
        );
        let rules = scan_doas(b"permit alice cmd \"a\\\\b\" \\\npermit nopass yamin\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].scope, Scope::Unknown);
        assert_eq!(
            doas_unmodelled(b"permit alice cmd \"a\\\\b\" \\\npermit nopass yamin\n"),
            vec![1]
        );
    }

    #[test]
    fn a_quote_alone_or_beside_a_leading_hash_is_modelled() {
        let scan = scan_sudoers(b"#include \"/etc/a b\"\nDefaults secure_path=\"/x\"\n");
        assert!(scan.unmodelled.is_empty());
        // A whole-line comment is dropped, not read for escapes.
        let scan = scan_sudoers(b"# it's \"quoted\" \\q\nalice ALL = ALL\n");
        assert!(scan.unmodelled.is_empty());
    }

    #[test]
    fn defaults_scope_reads_a_blank_before_its_sigil() {
        let scan = scan_sudoers(
            b"Defaults :bob !authenticate\n\
              Defaults @h !authenticate\n\
              Defaults\t>root\t!authenticate\n",
        );
        let scopes: Vec<Scope> = scan.rules.iter().map(|r| r.scope.clone()).collect();
        assert_eq!(
            scopes,
            vec![users(&["bob"]), Scope::Unknown, Scope::Unknown]
        );
    }

    #[test]
    fn authenticate_off_outside_defaults_is_unknown_and_may_share_a_line_with_a_tag() {
        let scan =
            scan_sudoers(b"bob ALL = NOPASSWD: !authenticate\nCmnd_Alias A = !authenticate\n");
        let grants: Vec<(Grant, Scope)> = scan
            .rules
            .iter()
            .map(|r| (r.grant, r.scope.clone()))
            .collect();
        assert_eq!(
            grants,
            vec![
                (Grant::Nopasswd, users(&["bob"])),
                (Grant::NoAuthenticate, Scope::Unknown)
            ]
        );
    }

    #[test]
    fn an_include_path_is_unescaped_the_way_sudo_unescapes_it() {
        assert_eq!(include_path(b"/etc/a\\ b rest"), b"/etc/a b");
        assert_eq!(include_path(b"/etc/a,b c"), b"/etc/a,b");
        assert_eq!(include_path(b"\"/etc/a b\" c"), b"/etc/a b");
        assert_eq!(include_path(b"\"/etc/a\\\"b\""), b"/etc/a\"b");
        assert_eq!(include_path(b"/etc/\\x41\\x4a"), b"/etc/AJ");
        assert_eq!(include_path(b"/etc/\\x4"), b"/etc/x4");
        assert_eq!(include_path(b"/etc/\\xZZ"), b"/etc/xZZ");
        assert_eq!(include_path(b"/etc/x\\"), b"/etc/x\\");
        assert_eq!(include_path(b""), b"");
        assert_eq!(include_path(b"\"unterminated"), b"unterminated");
    }

    #[test]
    fn denies_a_trailing_backslash_in_an_include_path_absorbing_the_callers_rule() {
        // Both the path with its backslash cut off (the backslash a
        // continuation) and the path with it kept (sudo's own reading, see
        // `denies_an_include_path_keeping_its_backslash_hiding_the_file_sudo_opens`)
        // are followed, and the rule on the next line, which the path may have
        // absorbed, is found: "maybe", never lost.
        for (directive, cut, kept) in [
            (
                &b"@include /etc/sudoers.d/x"[..],
                Include::File(b"/etc/sudoers.d/x".to_vec()),
                Include::File(b"/etc/sudoers.d/x\\".to_vec()),
            ),
            (
                b"#include /etc/sudoers.d/x",
                Include::File(b"/etc/sudoers.d/x".to_vec()),
                Include::File(b"/etc/sudoers.d/x\\".to_vec()),
            ),
            (
                b"@includedir /etc/sudoers.d",
                Include::Dir(b"/etc/sudoers.d".to_vec()),
                Include::Dir(b"/etc/sudoers.d\\".to_vec()),
            ),
            (
                b"#includedir /etc/sudoers.d",
                Include::Dir(b"/etc/sudoers.d".to_vec()),
                Include::Dir(b"/etc/sudoers.d\\".to_vec()),
            ),
        ] {
            let mut text = directive.to_vec();
            text.extend_from_slice(b"\\\nyamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            assert_eq!(scan.includes, vec![cut, kept], "{directive:?}");
            // The include marker and the rule the path may have absorbed.
            let grants: Vec<Grant> = scan.rules.iter().map(|rule| rule.grant).collect();
            assert_eq!(
                grants,
                vec![Grant::Include, Grant::Nopasswd],
                "{directive:?}"
            );
            assert!(scan.rules.iter().all(|rule| rule.scope == Scope::Unknown));
            assert_eq!(scan.unmodelled, vec![1], "{directive:?}");
        }
    }

    #[test]
    fn denies_an_include_continued_inside_its_quotes_hiding_the_file_sudo_opens() {
        // sudo 1.9.16p2: a backslash-newline inside the quotes of an include
        // path is dropped and the path goes on, so `"/etc/s4/a\` and `b"` open
        // `/etc/s4/ab`, a file none of the candidates names. These are the
        // observer's round-2 cases, byte for byte; each is run through the real
        // program and grants the caller. Following candidates cannot find the
        // file, so the line is reported as an include aido could not check.
        for (text, at) in [
            (&b"@include \"/etc/s4/a\\\nb\"\n"[..], 1), // q1_inc_quoted_cont.sudoers
            (&b"@include \"/etc/s4/a\\\n   b\"\n"[..], 1), // q2_inc_quoted_cont_lead.sudoers
            (&b"#include \"/etc/s4/a\\\nb\"\n"[..], 1), // q3_hashinc_quoted_cont.sudoers
            (&b"@includedir \"/etc/s5\\\nd\"\n"[..], 1), // q4_incdir_quoted_cont.sudoers
            (&b"#includedir \"/etc/s5\\\nd\"\n"[..], 1), // q5_hashincdir_quoted_cont.sudoers
            (&b"@include \"/etc/s4/a\\ \nb\"\n"[..], 1), // q6_inc_quoted_cont_blank.sudoers
            (&b"@include \"/etc/s4/a\\\r\nb\"\r\n"[..], 1), // q7_inc_quoted_cont_crlf.sudoers
            (
                b"Defaults:alice lecture_file=/etc/x\\ \n@include \"/etc/s4/a\\\nb\"\n",
                2,
            ), // q8_later_inc_quoted_cont.sudoers
        ] {
            let scan = scan_sudoers(text);
            let found: Vec<(usize, Grant, Scope)> = scan
                .rules
                .iter()
                .map(|rule| (rule.line, rule.grant, rule.scope.clone()))
                .collect();
            assert_eq!(
                found,
                vec![(at, Grant::Include, Scope::Unknown)],
                "{text:?}"
            );
        }
    }

    #[test]
    fn denies_an_include_path_starting_on_a_continuation_line_hiding_the_file_sudo_opens() {
        // sudo 1.9.16p2: `@include\` then the path on the next line opens the
        // path, a file the first line never names.
        for (text, at) in [
            (&b"@include \\\n/etc/s6/a\\\n"[..], 1), // n1_inc_path_on_next_line.sudoers
            (&b"#include \\\n/etc/s6/a\\\n"[..], 1), // n2_hashinc_path_on_next_line.sudoers
            (&b"@includedir \\\n/etc/s7\\\n"[..], 1), // n3_incdir_path_on_next_line.sudoers
            (&b"@include \\\n   /etc/s6/a\\\n"[..], 1), // n4_inc_path_on_next_line_lead.sudoers
            (&b"#includedir \\\n/etc/s7\\\n"[..], 1), // n5_hashincdir_path_on_next_line.sudoers
        ] {
            let scan = scan_sudoers(text);
            let found: Vec<(usize, Grant, Scope)> = scan
                .rules
                .iter()
                .map(|rule| (rule.line, rule.grant, rule.scope.clone()))
                .collect();
            assert_eq!(
                found,
                vec![(at, Grant::Include, Scope::Unknown)],
                "{text:?}"
            );
        }
    }

    #[test]
    fn denies_an_include_directive_split_across_a_join_hiding_its_file() {
        // The word itself is cut by the join: no physical line holds it. (A `#`
        // directive is a whole-line comment until the join, which is read as
        // one already, and unmodelled.)
        for directive in ["@incl", "@includ"] {
            let mut text = directive.as_bytes().to_vec();
            text.extend_from_slice(b"\\\n");
            text.extend_from_slice(if directive.ends_with("incl") {
                b"ude /etc/p\n"
            } else {
                b"e /etc/p\n"
            });
            let scan = scan_sudoers(&text);
            let found: Vec<(usize, Grant)> = scan
                .rules
                .iter()
                .map(|rule| (rule.line, rule.grant))
                .collect();
            assert_eq!(found, vec![(1, Grant::Include)], "{text:?}");
        }
    }

    #[test]
    fn a_settled_include_on_a_modelled_line_is_not_a_finding() {
        // Nothing is uncertain, so what is read is what the program reads.
        for text in [
            &b"@include /etc/p\n"[..],
            b"#include /etc/p\n",
            b"@includedir /etc/d\n",
            b"#includedir /etc/d\n",
        ] {
            assert!(scan_sudoers(text).rules.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn an_uncertain_line_naming_no_include_adds_no_include_finding() {
        let scan = scan_sudoers(b"Defaults lecture_file=/x\\ \nalice ALL=ALL\n");
        assert!(scan.rules.is_empty(), "{:?}", scan.rules);
    }

    #[test]
    fn an_include_on_a_later_physical_line_is_reported_on_that_line() {
        let scan = scan_sudoers(b"alice ALL=(ALL) ALL # a \\\n  # b \\\n@include /etc/p\\\n");
        let found: Vec<(usize, Grant)> = scan
            .rules
            .iter()
            .map(|rule| (rule.line, rule.grant))
            .collect();
        assert_eq!(found, vec![(3, Grant::Include)]);
    }

    #[test]
    fn denies_a_carriage_return_ending_a_later_include_line_hiding_the_file_sudo_opens() {
        // A CRLF file: `\r` is a line end to sudo, never part of a path, so no
        // candidate may carry one, and the line that holds the include with
        // its backslash kept (`/etc/q/p\`) is among them.
        let scan = scan_sudoers(
            b"alice ALL=(ALL) ALL # note \\\r\n@include /etc/q/p\\\r\n@includedir /etc/q/d\r\n",
        );
        let files: Vec<Vec<u8>> = scan
            .includes
            .iter()
            .map(|include| match include {
                Include::File(path) | Include::Dir(path) => path.clone(),
            })
            .collect();
        assert!(files.contains(&b"/etc/q/p".to_vec()), "{files:?}");
        assert!(files.contains(&b"/etc/q/p\\".to_vec()), "{files:?}");
        assert!(files.iter().all(|path| !path.ends_with(b"\r")), "{files:?}");
    }

    #[test]
    fn denies_an_include_path_keeping_its_backslash_hiding_the_file_sudo_opens() {
        // sudo 1.9.16p2 (`sudo -n true` as the caller, the grant in the file
        // named by the path as written): an include path is the one token that
        // keeps a final backslash, so `@include /etc/q/p\` opens the file `p\`
        // and not `p`, and the line after it is a rule of its own. Reading only
        // `p` credited the caller's grant to whoever `p` names. Both are
        // followed, and where the two readings agree there is one path.
        let file = |path: &[u8]| Include::File(path.to_vec());
        let dir = |path: &[u8]| Include::Dir(path.to_vec());
        for (text, includes) in [
            (
                &b"@include /etc/q/p\\\n"[..],
                vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
            ),
            (
                b"#include /etc/q/p\\\n",
                vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
            ),
            (
                b"@includedir /etc/qd\\\n",
                vec![dir(b"/etc/qd"), dir(b"/etc/qd\\")],
            ),
            (
                b"#includedir /etc/qd\\\n",
                vec![dir(b"/etc/qd"), dir(b"/etc/qd\\")],
            ),
            // The next line is a rule of its own to sudo, and no include.
            (
                b"@include /etc/q/p\\\nalice ALL=(ALL) ALL\n",
                vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
            ),
            // `\r\n` ends the line, and the carriage return is not in the path.
            (
                b"@include /etc/q/p\\\r\n",
                vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
            ),
            // A blank or a tab after the backslash is an escaped blank, which is
            // part of the path: sudo opens `p ` and `p<tab>`.
            (
                b"@include /etc/q/p\\ \n",
                vec![file(b"/etc/q/p"), file(b"/etc/q/p ")],
            ),
            (
                b"@include /etc/q/p\\\t\n",
                vec![file(b"/etc/q/p"), file(b"/etc/q/p\t")],
            ),
            (
                b"@include /etc/q/p\\ \\\n",
                vec![file(b"/etc/q/p "), file(b"/etc/q/p \\")],
            ),
            // One path where the readings agree: a blank before the backslash
            // ends the path, so the backslash is a continuation, and a quoted
            // path ends at its quote.
            (b"@include /etc/q/p \\\n", vec![file(b"/etc/q/p")]),
            (b"@include \"/etc/q/p\"\\\n", vec![file(b"/etc/q/p")]),
        ] {
            let scan = scan_sudoers(text);
            assert_eq!(scan.includes, includes, "{text:?}");
            assert_eq!(scan.unmodelled, vec![1], "{text:?}");
        }
        // `\\` is one backslash, and sudo opens `p\`: it is among the paths,
        // whatever else the join of the line with the next one makes of the
        // backslash left over.
        let scan = scan_sudoers(b"@include /etc/q/p\\\\\n");
        assert!(scan.includes.contains(&file(b"/etc/q/p\\")), "{scan:?}");
        // An include that does not end in a backslash is read once.
        let scan = scan_sudoers(b"@include /etc/q/p\n");
        assert_eq!(scan.includes, vec![file(b"/etc/q/p")]);
        assert!(scan.unmodelled.is_empty());
    }

    #[test]
    fn denies_an_include_on_a_later_line_keeping_its_backslash_hiding_the_file_sudo_opens() {
        // sudo 1.9.16p2: after `lecture_file=/etc/x\ ` or a comment that eats
        // its backslash the next line is a directive of its own, and `@include
        // /etc/q/p\` on it opens `p\`. Where the backslash does join, sudo
        // refuses the include; reading it anyway only reports more.
        let file = |path: &[u8]| Include::File(path.to_vec());
        let dir = |path: &[u8]| Include::Dir(path.to_vec());
        for head in [
            &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
            b"alice ALL=(ALL) ALL # note \\\n",
            b"Cmnd_Alias X = /bin/true \\\n",
        ] {
            for (directive, includes) in [
                (
                    &b"@include /etc/q/p\\\n"[..],
                    vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
                ),
                (
                    b"#include /etc/q/p\\\n",
                    vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")],
                ),
                (
                    b"@includedir /etc/qd\\\n",
                    vec![dir(b"/etc/qd"), dir(b"/etc/qd\\")],
                ),
                (
                    b"#includedir /etc/qd\\\n",
                    vec![dir(b"/etc/qd"), dir(b"/etc/qd\\")],
                ),
            ] {
                let mut text = head.to_vec();
                text.extend_from_slice(directive);
                let scan = scan_sudoers(&text);
                assert_eq!(scan.includes, includes, "{head:?} {directive:?}");
                assert_eq!(scan.unmodelled, vec![1, 2], "{head:?} {directive:?}");
            }
        }
        // Two includes on one joined line: each, with its backslash and
        // without.
        let scan = scan_sudoers(b"@include /etc/a\\\n@include /etc/b\\\n");
        assert_eq!(
            scan.includes,
            vec![
                file(b"/etc/a"),
                file(b"/etc/b"),
                file(b"/etc/a\\"),
                file(b"/etc/b\\"),
            ]
        );
        // A whole-line comment that ends in a backslash does not hide the
        // include below it.
        let scan = scan_sudoers(b"# note \\\n@include /etc/q/p\\\n");
        assert_eq!(scan.includes, vec![file(b"/etc/q/p"), file(b"/etc/q/p\\")]);
    }

    #[test]
    fn denies_an_include_on_a_line_the_program_did_not_join_hiding_the_callers_grant() {
        // sudo 1.9.16p2: `lecture_file=/etc/x\ ` ends in an escaped blank, and
        // `# note \` in a comment that eats its backslash, so neither joins the
        // line after it. An include that starts that line is a directive of its
        // own, and the file it names granted the caller `sudo -n true`. Joined
        // to the line above, it was never read.
        for head in [
            &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
            b"alice ALL=(ALL) ALL # note \\\n",
            // Where the backslash does join, sudo does not honour the include
            // (it is part of the joined line); reading it anyway only reports
            // more.
            b"Cmnd_Alias X = /bin/true \\\n",
        ] {
            for (directive, include) in [
                (
                    &b"@include /etc/sudo-extra\n"[..],
                    Include::File(b"/etc/sudo-extra".to_vec()),
                ),
                (
                    b"#include /etc/sudo-extra\n",
                    Include::File(b"/etc/sudo-extra".to_vec()),
                ),
                (
                    b"@includedir /etc/sudo-extra.d\n",
                    Include::Dir(b"/etc/sudo-extra.d".to_vec()),
                ),
                (
                    b"#includedir /etc/sudo-extra.d\n",
                    Include::Dir(b"/etc/sudo-extra.d".to_vec()),
                ),
            ] {
                let mut text = head.to_vec();
                text.extend_from_slice(directive);
                let scan = scan_sudoers(&text);
                assert_eq!(scan.includes, vec![include], "{head:?} {directive:?}");
                assert_eq!(scan.unmodelled, vec![1], "{head:?} {directive:?}");
            }
        }
        // An include is read where it starts a line, not where it is a word
        // in the middle of one.
        let scan = scan_sudoers(b"alice ALL=(ALL) ALL \\\n  and @include /etc/x\n");
        assert!(scan.includes.is_empty());
    }

    #[test]
    fn denies_a_continuation_splitting_a_doas_identity_as_another_users() {
        // OpenDoas 6.8.2 reads `10\` then `00` as the one word `1000` (uid
        // 1000, the caller, who then runs `doas -n true`) and `:2\` then `7` as
        // `:27` (gid 27, a group the caller holds); joined with a space they
        // named uid 10 and gid 2, someone else.
        for (text, whole) in [
            (&b"permit nopass 10\\\n00\n"[..], &b"permit nopass 1000"[..]),
            (b"permit nopass :2\\\n7\n", b"permit nopass :27"),
            (b"permit nopass :10\\\n00\n", b"permit nopass :1000"),
            (b"permit nopass 1\\\n0\\\n00\n", b"permit nopass 1000"),
            (b"permit nopass \"10\\\n00\"\n", b"permit nopass \"1000\""),
        ] {
            // The word is whole where the lines are glued with nothing, which
            // is how the program joins them...
            let read = logical_lines(text, is_hash_comment, Dialect::Doas);
            assert_eq!(read.logical[0].glued, whole, "{text:?}");
            // ...and it is not credited to whoever the first half names.
            let rules = scan_doas(text);
            assert_eq!(rules.len(), 1, "{text:?}");
            assert_eq!(rules[0].scope, Scope::Unknown, "{text:?}");
            assert_eq!(doas_unmodelled(text)[0], 1, "{text:?}");
        }
    }

    #[test]
    fn denies_a_doas_keyword_spelled_with_an_escape_hiding_the_callers_rule() {
        // OpenDoas 6.8.2 drops the backslash of `\s`, so `permit nopas\s yamin`
        // is a `nopass` rule for the caller, and `doas -n true` succeeds. The
        // line holds an escape this module does not model: it is unmodelled,
        // and the rule is found, as "maybe".
        for text in [
            &b"permit nopas\\s yamin\n"[..],
            b"permit n\\o\\p\\a\\s\\s yamin\n",
            b"permit nopass yamin \\q\n",
        ] {
            let rules = scan_doas(text);
            assert_eq!(rules.len(), 1, "{text:?}");
            assert_eq!(rules[0].scope, Scope::Unknown, "{text:?}");
            assert_eq!(doas_unmodelled(text), vec![1], "{text:?}");
        }
        // Every backslash is dropped from the second reading only: nothing is
        // found where the keyword is not there either way.
        assert!(scan_doas(b"permit nopa\\x yamin\n").is_empty());
        assert!(spelled_with_or_without_escapes(b"n\\op\\ass", b"nopass"));
        assert!(!spelled_with_or_without_escapes(b"n\\op\\ast", b"nopass"));
    }

    #[test]
    fn denies_a_tag_split_across_a_continuation_hiding_the_callers_rule() {
        // `nop\` then `ass` is `nopass` to OpenDoas; the sudo tag and
        // `!authenticate` are read the same way, in case.
        assert_eq!(scan_doas(b"permit nop\\\nass yamin\n").len(), 1);
        // No `nopass` anywhere on an uncertain line: no rule.
        assert!(scan_doas(b"permit alice cmd /bin/ls \\\nargs x\n").is_empty());
        let scan = scan_sudoers(b"yamin ALL=(ALL) NOPA\\\nSSWD: ALL\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].grant, Grant::Nopasswd);
        let scan = scan_sudoers(b"Defaults !auth\\\nenticate\n");
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.rules[0].grant, Grant::NoAuthenticate);
        assert_eq!(scan.rules[0].scope, Scope::Unknown);
    }

    #[test]
    fn denies_any_line_ending_in_a_backslash_hiding_the_callers_nopasswd_rule() {
        // The property: whatever the line before it is, a rule naming the
        // caller on the line after a backslash is found, never as someone
        // else's, and the file is unmodelled.
        for head in lines_ending_in_a_backslash() {
            let mut text = head.clone();
            text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
            let scan = scan_sudoers(&text);
            assert!(!scan.unmodelled.is_empty(), "{head:?}");
            let named_yamin = scan.rules.iter().any(|rule| {
                rule.grant == Grant::Nopasswd
                    && rule.text.windows(5).any(|w| w == b"yamin")
                    && rule.scope == Scope::Unknown
            });
            assert!(named_yamin, "{head:?}: {:?}", scan.rules);
            assert!(
                scan.rules.iter().all(|rule| rule.scope == Scope::Unknown),
                "{head:?}"
            );

            let mut text = head.clone();
            text.extend_from_slice(b"permit nopass yamin\n");
            let rules = scan_doas(&text);
            assert!(!doas_unmodelled(&text).is_empty(), "{head:?}");
            assert!(
                rules.iter().any(|rule| rule.scope == Scope::Unknown),
                "{head:?}"
            );
            assert!(
                rules.iter().all(|rule| rule.scope == Scope::Unknown),
                "{head:?}"
            );
        }
    }
}
