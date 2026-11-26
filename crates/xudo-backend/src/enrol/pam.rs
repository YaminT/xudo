//! Whether sudo's PAM `auth` stack is one xudo recognizes, and passes nobody
//! without the account's password.
//!
//! An allowlist, not a blocklist: PAM has too many spellings to list the bad
//! ones (four review rounds each found more). Every `auth` line sudo can reach
//! must be one of a few stock forms, on one of a few stock modules; anything
//! else is "not recognized" and enrol refuses. The files are read the way
//! libpam reads them (continued lines, `#` comments, `@include` and `include`
//! in any case, `/usr/lib/pam.d` after `/etc/pam.d`, `other` for a service
//! with no `auth` line), and then every path through the stack is walked:
//! no path may end in a pass when `pam_unix` refuses.

use std::path::Path;

use crate::paths_to_root::{HostView, Lookup};

/// How deep includes may nest before the scan gives up.
const MAX_DEPTH: usize = 8;
/// Where libpam looks for a service, in order.
const DIRS: [&str; 2] = ["/etc/pam.d", "/usr/lib/pam.d"];

/// The modules a recognized stack may name. All but `pam_unix`, `pam_deny`
/// and `pam_permit` are judged as if they could return anything.
const MODULES: [&str; 14] = [
    "pam_unix",
    "pam_deny",
    "pam_permit",
    "pam_succeed_if",
    "pam_env",
    "pam_faildelay",
    "pam_nologin",
    "pam_limits",
    "pam_systemd",
    "pam_keyinit",
    "pam_loginuid",
    "pam_localuser",
    "pam_usertype",
    "pam_cap",
];

/// What libpam does with one module's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    Ok,
    Done,
    Bad,
    Ignore,
    Jump(usize),
}

/// The recognized controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Control {
    Required,
    Requisite,
    Sufficient,
    Optional,
    /// `[success=<act> default=ignore]`, either order: Debian's `pam_unix`.
    OnSuccess(Act),
    /// `[default=1 ignore=ignore success=ok]`: Fedora's `pam_usertype`.
    SkipOnFail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    Ignore,
    Fail,
}

struct Line {
    at: String,
    module: &'static str,
    control: Control,
}

/// Every reason enrol must refuse because of PAM, each naming a file.
pub(super) fn blockers(host: &dyn HostView) -> Vec<String> {
    let mut out = Vec::new();
    let mut fallback = false;
    for service in ["sudo", "sudo-i"] {
        // Not every sudo has `sudo-i`; libpam then reads `other`.
        if service == "sudo-i" && find(host, service).is_none() {
            fallback = true;
            continue;
        }
        fallback |= judge(host, service, &mut out);
    }
    // No `other` at all: libpam cannot start the service, which passes nobody.
    if fallback && find(host, "other").is_some() {
        judge(host, "other", &mut out);
    }
    out
}

/// The first of libpam's directories that has `name`.
fn find(host: &dyn HostView, name: &str) -> Option<String> {
    DIRS.iter()
        .map(|dir| format!("{dir}/{name}"))
        .find(|path| !matches!(host.read(Path::new(path)), Lookup::Missing))
}

/// Judges one service into `out`; whether it has no `auth` line, so that
/// libpam answers from `other`.
fn judge(host: &dyn HostView, service: &str, out: &mut Vec<String>) -> bool {
    let before = out.len();
    let mut stack = Vec::new();
    walk(host, service, 0, &mut Vec::new(), &mut stack, out);
    if out.len() > before {
        return false;
    }
    if let Some(line) = passes(&stack).and_then(|at| stack.get(at)) {
        out.push(format!(
            "{}: PAM can pass sudo without the account's password from here ({})",
            line.at, line.module
        ));
    }
    stack.is_empty()
}

/// Appends the `auth` lines of `name`, includes inlined, to `stack`.
fn walk(
    host: &dyn HostView,
    name: &str,
    depth: usize,
    chain: &mut Vec<String>,
    stack: &mut Vec<Line>,
    out: &mut Vec<String>,
) {
    let file = find(host, name).unwrap_or_else(|| format!("/etc/pam.d/{name}"));
    if chain.contains(&file) {
        out.push(format!("could not examine {file}: it includes itself"));
        return;
    }
    if depth > MAX_DEPTH {
        out.push(format!(
            "could not examine {file}: includes nest deeper than {MAX_DEPTH}"
        ));
        return;
    }
    let text = match host.read(Path::new(&file)) {
        Lookup::Found(bytes) => bytes,
        Lookup::Missing => return out.push(format!("could not examine {file}: no such file")),
        Lookup::Unreadable(why) => return out.push(format!("could not examine {file}: {why}")),
    };
    let lines = match std::str::from_utf8(&text) {
        Ok(text) if !text.contains('\0') => logical_lines(text),
        _ => Err("not text".to_owned()),
    };
    let lines = match lines {
        Ok(lines) => lines,
        Err(why) => return out.push(format!("could not examine {file}: {why}")),
    };
    chain.push(file.clone());
    // A `requisite pam_deny` seen in this file: a `pam_permit` after it is
    // reached only by a stack that already passed.
    let mut denied = false;
    for (line_no, line) in lines {
        let at = format!("{file} line {line_no}");
        match read_line(&line, denied) {
            Ok(Read::Include(target)) => {
                walk(host, target, depth.saturating_add(1), chain, stack, out);
            }
            Ok(Read::Auth(module, control)) => {
                denied |= module == "pam_deny" && control == Control::Requisite;
                stack.push(Line {
                    at,
                    module,
                    control,
                });
            }
            Ok(Read::Other) => {}
            Err(why) => out.push(format!("{at}: PAM stack not recognized: {why}")),
        }
    }
    chain.pop();
}

/// The lines of a PAM file as libpam assembles them, numbered by the line
/// each starts on: leading spaces and tabs skipped, a blank or `#` line
/// dropped (even inside a continuation), a `#` later in a line ending it,
/// and a line ending in `\` (spaces and tabs after it ignored) joined to the
/// next with a space.
fn logical_lines(text: &str) -> Result<Vec<(usize, String)>, String> {
    let mut out = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for (index, raw) in text.split('\n').enumerate() {
        let line = raw.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (body, more) = if let Some((body, _)) = line.split_once('#') {
            (body, false)
        } else {
            let line = line.trim_end_matches([' ', '\t']);
            line.strip_suffix('\\')
                .map_or((line, false), |body| (body, true))
        };
        let (start, mut joined) = open
            .take()
            .unwrap_or((index.saturating_add(1), String::new()));
        joined.push(' ');
        joined.push_str(body);
        if more {
            open = Some((start, joined));
        } else {
            out.push((start, joined));
        }
    }
    match open {
        Some((start, _)) => Err(format!("line {start} is continued past the end")),
        None => Ok(out),
    }
}

enum Read<'a> {
    Include(&'a str),
    Auth(&'static str, Control),
    Other,
}

/// One assembled line, or why it is not a recognized form.
fn read_line(line: &str, denied: bool) -> Result<Read<'_>, String> {
    let line = line.trim_start_matches([' ', '\t']);
    let (kind, rest) = line.split_once([' ', '\t']).unwrap_or((line, ""));
    if kind.eq_ignore_ascii_case("@include") {
        return match words(rest).as_slice() {
            [target] => include(target),
            _ => Err("`@include` must name exactly one file".to_owned()),
        };
    }
    let bare = kind.strip_prefix('-').unwrap_or(kind);
    if !["auth", "account", "session", "password"]
        .iter()
        .any(|known| bare.eq_ignore_ascii_case(known))
    {
        // libpam makes a line of an unknown type a failing `auth` line, and
        // its control still applies: a jump there skips the deny.
        return Err(format!("unknown type `{kind}`"));
    }
    if !bare.eq_ignore_ascii_case("auth") {
        return Ok(Read::Other);
    }
    let rest = rest.trim_start_matches([' ', '\t']);
    // A bracket ends at the first `]`, with no space needed after it.
    let (control, rest) = if let Some(inside) = rest.strip_prefix('[') {
        let (inside, after) = inside
            .split_once(']')
            .ok_or_else(|| "a `[` control has no `]`".to_owned())?;
        (bracket(inside)?, after)
    } else {
        let (word, after) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
        let lower = word.to_ascii_lowercase();
        let control = match lower.as_str() {
            "required" => Control::Required,
            "requisite" => Control::Requisite,
            "sufficient" => Control::Sufficient,
            "optional" => Control::Optional,
            "include" => {
                return match words(after).as_slice() {
                    [target] => include(target),
                    _ => Err("`include` must name exactly one file".to_owned()),
                };
            }
            _ => return Err(format!("control `{word}` is not one xudo recognizes")),
        };
        (control, after)
    };
    let Some(path) = words(rest).first().copied() else {
        return Err("the line names no module".to_owned());
    };
    let module = path
        .strip_suffix(".so")
        .and_then(|name| MODULES.iter().find(|known| **known == name))
        .ok_or_else(|| format!("module `{path}` is not one xudo recognizes"))?;
    let plain = matches!(control, Control::Required | Control::Requisite);
    let fits = match *module {
        "pam_unix" => !matches!(control, Control::SkipOnFail),
        "pam_deny" => !matches!(control, Control::OnSuccess(_) | Control::SkipOnFail),
        "pam_permit" if !denied => {
            return Err("`pam_permit` without a `requisite pam_deny` before it".to_owned());
        }
        "pam_permit" | "pam_succeed_if" => plain,
        "pam_localuser" | "pam_usertype" => {
            plain || control == Control::Optional || control == Control::SkipOnFail
        }
        _ => plain || control == Control::Optional,
    };
    if fits {
        Ok(Read::Auth(module, control))
    } else {
        Err(format!(
            "`{module}` with that control is not a form xudo recognizes"
        ))
    }
}

/// The words of `text`, split where libpam splits them.
fn words(text: &str) -> Vec<&str> {
    text.split([' ', '\t'])
        .filter(|word| !word.is_empty())
        .collect()
}

/// An include target: a file in libpam's directories, by bare name.
fn include(target: &str) -> Result<Read<'_>, String> {
    if target.contains('/') {
        Err(format!("include `{target}` is not a bare file name"))
    } else {
        Ok(Read::Include(target))
    }
}

/// The bracket controls stock distributions write, and no other. libpam reads
/// a bracket case-sensitively, and a jump of 0 is an error to it.
fn bracket(inside: &str) -> Result<Control, String> {
    let mut pairs: Vec<&str> = inside
        .split([' ', '\t'])
        .filter(|pair| !pair.is_empty())
        .collect();
    pairs.sort_unstable();
    let control = match pairs.as_slice() {
        ["default=ignore", success] => success.strip_prefix("success=").and_then(|act| {
            match act {
                "ok" => Some(Act::Ok),
                "done" => Some(Act::Done),
                digits if digits.bytes().all(|b| b.is_ascii_digit()) => {
                    digits.parse().ok().filter(|skip| *skip > 0).map(Act::Jump)
                }
                _ => None,
            }
            .map(Control::OnSuccess)
        }),
        ["default=1", "ignore=ignore", "success=ok"] => Some(Control::SkipOnFail),
        // `required`, spelled out.
        [
            "default=bad",
            "ignore=ignore",
            "new_authtok_reqd=ok",
            "success=ok",
        ] => Some(Control::Required),
        _ => None,
    };
    control.ok_or_else(|| format!("control `[{inside}]` is not one xudo recognizes"))
}

/// What a module can return when the password is not given: `pam_unix` and
/// `pam_deny` only fail, `pam_permit` only passes, anything else anything.
fn outcomes(module: &str) -> &'static [Outcome] {
    match module {
        "pam_unix" | "pam_deny" => &[Outcome::Fail],
        "pam_permit" => &[Outcome::Success],
        _ => &[Outcome::Success, Outcome::Ignore, Outcome::Fail],
    }
}

/// libpam's action for a result under a control. A failure that libpam
/// treats otherwise (`new_authtok_reqd`) only ever ends in a failure too.
fn act(control: Control, outcome: Outcome) -> Act {
    match (control, outcome) {
        (Control::Sufficient, Outcome::Success) => Act::Done,
        (Control::OnSuccess(act), Outcome::Success) => act,
        (_, Outcome::Success) => Act::Ok,
        (Control::Required | Control::Requisite, Outcome::Fail) => Act::Bad,
        (Control::SkipOnFail, Outcome::Fail) => Act::Jump(1),
        (_, Outcome::Ignore | Outcome::Fail) => Act::Ignore,
    }
}

/// Walks every path through `stack` when the password is not given; the
/// line whose success some path ends in a pass on. A `bad` or `die` can
/// never be undone, so those paths end there. Per line, a path is either
/// undecided or passing (and from which line).
fn passes(stack: &[Line]) -> Option<usize> {
    // Each path as (the line it is at, the line it passes from, if any). One
    // undecided and one passing path per line is all the walk needs.
    let mut paths: Vec<(usize, Option<usize>)> = vec![(0, None)];
    for (at, line) in stack.iter().enumerate() {
        let here: Vec<Option<usize>> = paths
            .iter()
            .filter(|(to, _)| *to == at)
            .map(|(_, from)| *from)
            .collect();
        let next_line = at.saturating_add(1);
        for state in here {
            for outcome in outcomes(line.module) {
                let (to, state) = match act(line.control, *outcome) {
                    Act::Ok => (next_line, Some(state.unwrap_or(at))),
                    Act::Done => return Some(state.unwrap_or(at)),
                    Act::Bad => continue,
                    Act::Ignore => (next_line, state),
                    Act::Jump(skip) => (next_line.saturating_add(skip).min(stack.len()), state),
                };
                if !paths
                    .iter()
                    .any(|(other, from)| *other == to && from.is_some() == state.is_some())
                {
                    paths.push((to, state));
                }
            }
        }
    }
    paths
        .into_iter()
        .find_map(|(to, from)| from.filter(|_| to == stack.len()))
}

#[cfg(test)]
mod tests {
    use super::{Act, Control, Line, passes};

    fn stack(lines: &[(&'static str, Control)]) -> Vec<Line> {
        lines
            .iter()
            .enumerate()
            .map(|(at, (module, control))| Line {
                at: format!("line {at}"),
                module,
                control: *control,
            })
            .collect()
    }

    /// The walk is the backstop under the allowlist: it judges forms the
    /// allowlist does not let through today, so widening the list later
    /// cannot skip it.
    #[test]
    fn the_walk_finds_a_pass_the_allowlist_would_never_let_through() {
        // `sufficient` on a module that can pass ends the stack there.
        let done = stack(&[
            ("pam_env", Control::Sufficient),
            ("pam_deny", Control::Required),
        ]);
        assert_eq!(passes(&done), Some(0));
        // A success jump over the deny, from an earlier pass.
        let jump = stack(&[
            ("pam_env", Control::Required),
            ("pam_cap", Control::OnSuccess(Act::Jump(1))),
            ("pam_deny", Control::Requisite),
        ]);
        assert_eq!(passes(&jump), Some(0));
        // `done` after a pass keeps the line that passed first.
        let later = stack(&[
            ("pam_permit", Control::Required),
            ("pam_cap", Control::OnSuccess(Act::Done)),
        ]);
        assert_eq!(passes(&later), Some(0));
        // A jump past the end, from nothing that passed, passes nobody.
        let off_end = stack(&[
            ("pam_usertype", Control::SkipOnFail),
            ("pam_deny", Control::Required),
        ]);
        assert_eq!(passes(&off_end), None);
        assert_eq!(passes(&[]), None);
    }
}
