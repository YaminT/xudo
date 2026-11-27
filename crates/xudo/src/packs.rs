//! `xudo rules`: add, list and remove rule packs.
//!
//! `add` and `remove` without `--reviewed` run as the operator: they judge the
//! rules with and without the pack ([`xudo_policy::pack::review`]: every test,
//! a near miss per harness action, registered labels, the lint errors of
//! `xudo check`), print what each harness, the password path and everyone gain
//! and lose, by rule and on the engine, every `gtfobins-waiver` and every new
//! lint warning, and a token. They write nothing. Only that token, handed back
//! with `--reviewed` through the machine's own sudo, changes anything: the root
//! side checks everything again from root's own reading of `/etc/xudo` and
//! refuses when the token it computes differs, because the pack, the rules,
//! the registry or `--allow-waivers` are not what was reviewed (see
//! `xudo_sys::add_pack`). Nothing is fetched and nothing updates itself.

use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use xudo_policy::pack::{
    Change, PackRefusal, Review, header_of, installed_by_xudo, review, with_pack, without_pack,
};
use xudo_policy::{ExitCode, RuleFile, load_policy_with_registry};
use xudo_sys::{Installer, MAX_PACK_BYTES, PackError, PackRequest};

use crate::check::{path_under_warnings, safe};
use crate::rules::{LoadedRules, read_rule_files, registry_beside};

/// What `xudo rules` can do.
#[derive(Debug, Subcommand)]
pub enum RulesAction {
    /// Check a rule pack and show what it changes. Writes nothing.
    ///
    /// With `--reviewed`, and as root (through sudo, which asks your
    /// password), check it again and install it into /etc/xudo/rules.d.
    Add {
        /// The pack: a rule file with a `[pack]` header.
        file: PathBuf,

        /// The token the review printed. Installs only this change: these
        /// bytes, onto the rules the review saw.
        #[arg(long, value_name = "TOKEN")]
        reviewed: Option<String>,

        /// Accept a pack whose rules carry a `gtfobins-waiver`. Needed for
        /// the review and the sudo step alike; read every waiver it prints.
        #[arg(long)]
        allow_waivers: bool,
    },

    /// List the rule packs in the rules directory.
    List,

    /// Show what removing a rule pack `xudo rules add` installed changes.
    /// Writes nothing.
    ///
    /// With `--reviewed`, and as root, remove it.
    Remove {
        /// The pack's name.
        name: String,

        /// The token the review printed.
        #[arg(long, value_name = "TOKEN")]
        reviewed: Option<String>,
    },
}

/// Runs one `xudo rules` action against the rules in `dir`.
pub(crate) fn run(
    dir: &Path,
    installer: &dyn Installer,
    action: &RulesAction,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    match action {
        RulesAction::Add {
            file,
            reviewed: None,
            allow_waivers,
        } => preview_add(dir, file, *allow_waivers, out, err),
        RulesAction::Add {
            file,
            reviewed: Some(reviewed),
            allow_waivers,
        } => match read_pack(file) {
            Ok(bytes) => {
                let request = PackRequest {
                    bytes,
                    reviewed: reviewed.clone(),
                    allow_waivers: *allow_waivers,
                };
                finish(installer.pack_add(&request), "installed", out, err)
            }
            Err(why) => refuse(err, &why, ExitCode::Unusable),
        },
        RulesAction::List => list(dir, out, err),
        RulesAction::Remove {
            name,
            reviewed: None,
        } => preview_remove(dir, name, out, err),
        RulesAction::Remove {
            name,
            reviewed: Some(reviewed),
        } => finish(installer.pack_remove(name, reviewed), "removed", out, err),
    }
}

/// The pack's bytes, bounded.
fn read_pack(file: &Path) -> Result<Vec<u8>, String> {
    let cannot = |error: std::io::Error| format!("cannot read {}: {error}", file.display());
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .and_then(|opened| {
            opened
                .take(
                    u64::try_from(MAX_PACK_BYTES)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut bytes)
        })
        .map_err(cannot)?;
    if bytes.len() > MAX_PACK_BYTES {
        return Err(format!(
            "{} is larger than {MAX_PACK_BYTES} bytes, so it is not a rule pack",
            file.display()
        ));
    }
    Ok(bytes)
}

fn print_review(review: &Review, out: &mut dyn Write) {
    let lines = review.lines();
    let effects = review.effect_lines();
    if lines.is_empty() && effects.is_empty() {
        let _ = writeln!(out, "no caller gains or loses anything");
    }
    for line in lines {
        let _ = writeln!(out, "  {}", safe(&line));
    }
    if !effects.is_empty() {
        let _ = writeln!(
            out,
            "what the engine decides differently, for the commands the rules' tests and \
             examples name:"
        );
    }
    for line in effects {
        let _ = writeln!(out, "  {}", safe(&line));
    }
    if !review.waivers.is_empty() {
        let _ = writeln!(
            out,
            "GTFOBins waivers: each lets a harness run a program with a known way out; read each:"
        );
    }
    for waiver in &review.waivers {
        let _ = writeln!(out, "  {}", safe(waiver));
    }
}

/// The lint warnings of `xudo check` the change adds: overlaps and
/// `path-under` matchers. They do not block; the operator should read them.
fn new_warnings(
    before: &[RuleFile],
    after: &[RuleFile],
    registry: &Result<Vec<xudo_policy::HarnessFile>, String>,
) -> Vec<String> {
    let warnings = |files: &[RuleFile]| -> Vec<String> {
        load_policy_with_registry(files.to_vec(), registry.as_deref().map_err(Clone::clone))
            .map(|loaded| {
                let rules = &loaded.rules;
                let mut found: Vec<String> =
                    rules.overlaps().iter().map(ToString::to_string).collect();
                found.extend(path_under_warnings(rules));
                found
            })
            .unwrap_or_default()
    };
    let old = warnings(before);
    warnings(after)
        .into_iter()
        .filter(|warning| !old.contains(warning))
        .collect()
}

/// Judges a change, prints it and the command that makes it, writes nothing.
fn show(
    dir: &Path,
    before: Vec<RuleFile>,
    after: Vec<RuleFile>,
    change: Change<'_>,
    [title, command]: [&str; 2],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let registry = registry_beside(dir);
    let warnings = new_warnings(&before, &after, &registry);
    let review = match review(before, after, &registry, change) {
        Ok(review) => review,
        Err(refusal) => return refused(err, &refusal),
    };
    let _ = writeln!(out, "{title}");
    print_review(&review, out);
    if !warnings.is_empty() {
        let _ = writeln!(out, "new lint warnings (they do not block):");
    }
    for warning in &warnings {
        let _ = writeln!(out, "  {}", safe(warning));
    }
    let _ = writeln!(
        out,
        "\nEvery check passed. Nothing was changed. To make exactly this change, onto exactly \
         these rules, run as root:\n  {}",
        command.replace("{token}", &review.token)
    );
    ExitCode::Delegated
}

fn rule_files(dir: &Path) -> Result<Vec<RuleFile>, String> {
    read_rule_files(dir)
        .map(|files| files.into_iter().map(|(_, file)| file).collect())
        .map_err(|error| error.to_string())
}

/// `add` as the operator: judge and show, write nothing.
fn preview_add(
    dir: &Path,
    file: &Path,
    allow_waivers: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let bytes = match read_pack(file) {
        Ok(bytes) => bytes,
        Err(why) => return refuse(err, &why, ExitCode::Unusable),
    };
    let header = match header_of(&bytes) {
        Ok(header) => header,
        Err(refusal) => return refuse(err, &refusal.to_string(), ExitCode::LintError),
    };
    let before = match rule_files(dir) {
        Ok(files) => files,
        Err(why) => return refuse(err, &why, ExitCode::Unusable),
    };
    let after = with_pack(&before, &header, &bytes);
    let title = format!(
        "pack {} {} for {}",
        header.name,
        header.version,
        if header.harnesses.is_empty() {
            "no harness".to_owned()
        } else {
            header.harnesses.join(", ")
        }
    );
    let command = format!(
        "sudo xudo rules add{} --reviewed {{token}} {}",
        if allow_waivers {
            " --allow-waivers"
        } else {
            ""
        },
        safe(&file.display().to_string())
    );
    let change = Change::Add {
        pack: &bytes,
        allow_waivers,
    };
    show(dir, before, after, change, [&title, &command], out, err)
}

/// `remove` as the operator: judge and show, write nothing.
fn preview_remove(dir: &Path, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let before = match rule_files(dir) {
        Ok(files) => files,
        Err(why) => return refuse(err, &why, ExitCode::Unusable),
    };
    let Some(after) = without_pack(&before, name) else {
        return refuse(
            err,
            &PackError::NotInstalled(name.to_owned()).to_string(),
            ExitCode::Unusable,
        );
    };
    let title = format!("removing pack {}", safe(name));
    let command = format!("sudo xudo rules remove --reviewed {{token}} {}", safe(name));
    let change = Change::Remove { name };
    show(dir, before, after, change, [&title, &command], out, err)
}

/// Prints a refusal that came from a check, one problem per line.
fn refused(err: &mut dyn Write, refusal: &PackRefusal) -> ExitCode {
    match refusal {
        PackRefusal::Problems(found) => {
            let _ = writeln!(err, "xudo: the change is refused; nothing was changed:");
            for problem in found {
                let _ = writeln!(err, "  {}", safe(problem));
            }
            ExitCode::LintError
        }
        PackRefusal::Waivers(found) => {
            let _ = writeln!(
                err,
                "xudo: the pack waives GTFOBins refusals; read each, then pass --allow-waivers to \
                 both `xudo rules add` and the sudo step; nothing was changed:"
            );
            for waiver in found {
                let _ = writeln!(err, "  {}", safe(waiver));
            }
            ExitCode::LintError
        }
        other => refuse(err, &other.to_string(), ExitCode::LintError),
    }
}

/// Reports what the root side did, or why it did nothing.
fn finish(
    result: Result<xudo_sys::PackReport, PackError>,
    done: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    match result {
        Ok(report) => {
            print_review(&report.review, out);
            let _ = writeln!(out, "{done} {}", report.path);
            for warning in &report.warnings {
                let _ = writeln!(err, "xudo: warning: {}", safe(warning));
            }
            ExitCode::Delegated
        }
        Err(PackError::Refused(refusal)) => refused(err, &refusal),
        Err(error) => refuse(err, &error.to_string(), ExitCode::Unusable),
    }
}

/// `list`: every pack in the rules directory, and whether xudo installed it.
fn list(dir: &Path, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let loaded = match LoadedRules::from_dir(dir) {
        Ok(loaded) => loaded,
        Err(error) => return refuse(err, &error.to_string(), ExitCode::Unusable),
    };
    if loaded.packs().is_empty() {
        let _ = writeln!(out, "No rule packs.");
    }
    for pack in loaded.packs() {
        let ours = std::fs::read(dir.join(&pack.file)).is_ok_and(|bytes| installed_by_xudo(&bytes));
        let header = &pack.header;
        let _ = writeln!(
            out,
            "{} {} for={} {} ({})",
            header.name,
            header.version,
            if header.harnesses.is_empty() {
                "-".to_owned()
            } else {
                header.harnesses.join(",")
            },
            safe(&pack.file),
            if ours {
                "installed by xudo rules add"
            } else {
                "written by hand; xudo rules remove leaves it"
            }
        );
    }
    ExitCode::Delegated
}

fn refuse(err: &mut dyn Write, reason: &str, code: ExitCode) -> ExitCode {
    let _ = writeln!(err, "xudo: {}", safe(reason));
    code
}

#[cfg(test)]
mod tests;
