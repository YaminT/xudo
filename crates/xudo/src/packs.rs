//! `xudo rules`: add, list and remove rule packs.
//!
//! `add` without `--reviewed` runs as the operator: it reads the pack, judges
//! the rules with it ([`xudo_policy::pack::review`]: every test, a near miss
//! per harness action, registered labels, the lint errors of `xudo check`),
//! prints what each harness and the password path gain and lose, and the
//! pack's SHA-256. It writes nothing. Only that digest, handed back with
//! `--reviewed` through the machine's own sudo, installs: the root side checks
//! everything again from root's own reading of `/etc/xudo` before the rename
//! (see `xudo_sys::add_pack`). Nothing is fetched and nothing updates itself.

use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use xudo_backend::snippet::MANAGED_MARKER;
use xudo_policy::pack::{PackRefusal, Review, digest, header_of, review};
use xudo_policy::{ExitCode, RuleFile};
use xudo_sys::{Installer, MAX_PACK_BYTES, PackError, PackRequest, installed_bytes};

use crate::check::safe;
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

        /// The SHA-256 the review printed. Installs only these exact bytes.
        #[arg(long, value_name = "SHA256")]
        reviewed: Option<String>,
    },

    /// List the rule packs in the rules directory.
    List,

    /// Remove a rule pack `xudo rules add` installed. Needs root.
    Remove {
        /// The pack's name.
        name: String,
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
        } => preview(dir, file, out, err),
        RulesAction::Add {
            file,
            reviewed: Some(reviewed),
        } => match read_pack(file) {
            Ok(bytes) => {
                let request = PackRequest {
                    bytes,
                    reviewed: reviewed.clone(),
                };
                finish(installer.pack_add(&request), "installed", out, err)
            }
            Err(why) => refuse(err, &why, ExitCode::Unusable),
        },
        RulesAction::List => list(dir, out, err),
        RulesAction::Remove { name } => finish(installer.pack_remove(name), "removed", out, err),
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
    if lines.is_empty() {
        let _ = writeln!(out, "no caller gains or loses anything");
    }
    for line in lines {
        let _ = writeln!(out, "  {}", safe(&line));
    }
}

/// `add` as the operator: judge and show, write nothing.
fn preview(dir: &Path, file: &Path, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let bytes = match read_pack(file) {
        Ok(bytes) => bytes,
        Err(why) => return refuse(err, &why, ExitCode::Unusable),
    };
    let header = match header_of(&bytes) {
        Ok(header) => header,
        Err(refusal) => return refuse(err, &refusal.to_string(), ExitCode::LintError),
    };
    let before: Vec<RuleFile> = match read_rule_files(dir) {
        Ok(files) => files.into_iter().map(|(_, file)| file).collect(),
        Err(error) => return refuse(err, &error.to_string(), ExitCode::Unusable),
    };
    let name = header.file_name().into_bytes();
    let after = before
        .iter()
        .filter(|found| found.name != name)
        .cloned()
        .chain(std::iter::once(RuleFile {
            name: name.clone(),
            bytes: installed_bytes(&bytes),
        }))
        .collect();
    let review = match review(before, after, &registry_beside(dir)) {
        Ok(review) => review,
        Err(refusal) => return refused(err, &refusal),
    };
    let hash = digest(&bytes);
    let _ = writeln!(
        out,
        "pack {} {} for {}",
        header.name,
        header.version,
        if header.harnesses.is_empty() {
            "no harness".to_owned()
        } else {
            header.harnesses.join(", ")
        }
    );
    print_review(&review, out);
    let _ = writeln!(
        out,
        "\nEvery check passed. Nothing was installed. To install exactly this file, run as root:\n  \
         sudo xudo rules add --reviewed {hash} {}",
        safe(&file.display().to_string())
    );
    ExitCode::Delegated
}

/// Prints a refusal that came from a check, one problem per line.
fn refused(err: &mut dyn Write, refusal: &PackRefusal) -> ExitCode {
    match refusal {
        PackRefusal::Problems(found) => {
            let _ = writeln!(err, "xudo: the pack is refused; nothing was installed:");
            for problem in found {
                let _ = writeln!(err, "  {}", safe(problem));
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
        let ours = std::fs::read(dir.join(&pack.file))
            .is_ok_and(|bytes| bytes.starts_with(MANAGED_MARKER.as_bytes()));
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
