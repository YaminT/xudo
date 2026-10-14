//! `ido add`: writing the agent instructions into `AGENTS.md` and its kin.
//!
//! The block is spliced between sentinel markers, so a second run updates the
//! block rather than adding another, and everything outside the markers is
//! kept byte for byte. The write never clobbers: a first modification backs the
//! original up to `<file>.ido-backup`, and the new contents go to a temporary
//! file in the same directory, are synced, and are renamed into place.
//!
//! A relative path may not leave the current directory, so a stray `ido add`
//! cannot rewrite a configuration file somewhere else; naming such a file takes
//! an absolute path, which is a deliberate act. A symlink is refused rather
//! than followed, for the same reason.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use crate::error::IdoError;

/// Opening marker. The version lets a later `ido` recognise and replace an
/// older block.
pub const BEGIN: &str = "<!-- ido:begin v1 -->";

/// Prefix shared by every version's opening marker.
const BEGIN_PREFIX: &str = "<!-- ido:begin";

/// Closing marker.
pub const END: &str = "<!-- ido:end -->";

/// The instructions, in short imperative sentences: this text is parsed by a
/// model, and hedging produces exactly the ambiguity that gets misread.
pub const BLOCK: &str = "<!-- ido:begin v1 -->
## Privileged and high-consequence commands

Do not run commands that need sudo. Do not run cloud CLI commands that write.

Queue them for the user instead:

    ido queue -m \"<why>\" -- <command> <args>

Example:

    ido queue -m \"install ripgrep for code search\" -- apt-get install -y ripgrep

The user runs `ido` later and picks what to run. Do not wait for it. Do not ask
the user to run the command by hand.

If two commands must run in order, put them in one group:

    ido queue --group deploy --step 1 -- terraform plan -out=tf.plan
    ido queue --group deploy --step 2 -- terraform apply tf.plan

Rules:
- Queue one command per call.
- Write a real argument list after `--`. Do not write a shell string.
- Do not queue the same command twice.
- Say what you queued. Then say: \"Run `ido` to execute it.\"
<!-- ido:end -->
";

/// File names `ido add` will write. Anything else is refused: this command
/// writes agent instruction files, and only those.
pub const RECOGNISED: [&str; 5] = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    "copilot-instructions.md",
];

/// What `ido add` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Added {
    /// The file did not exist and now holds the block.
    Created(PathBuf),
    /// The block was added or replaced.
    Updated(PathBuf),
    /// The block was already current; nothing was written.
    Unchanged(PathBuf),
}

/// Splices the block into `existing`.
///
/// # Errors
///
/// Refuses markers it cannot pair up exactly — an opening marker without a
/// closing one, a closing one first, or more than one block — rather than
/// guessing which text is ours to replace.
pub fn splice(existing: &str) -> Result<String, IdoError> {
    let begins = existing.matches(BEGIN_PREFIX).count();
    let ends = existing.matches(END).count();
    if begins == 0 && ends == 0 {
        let mut out = existing.to_owned();
        if !out.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
        out.push_str(BLOCK);
        return Ok(out);
    }
    let malformed = || {
        IdoError::Refused(
            "the file's ido markers do not pair up (one `<!-- ido:begin` followed by one \
             `<!-- ido:end -->`); fix them by hand, ido will not guess which text is its own"
                .to_owned(),
        )
    };
    if begins != 1 || ends != 1 {
        return Err(malformed());
    }
    // Both exist: each was counted exactly once above.
    let start = existing.find(BEGIN_PREFIX).unwrap_or_default();
    let end_at = existing.find(END).unwrap_or_default();
    if end_at < start {
        return Err(malformed());
    }
    let after = end_at.saturating_add(END.len());
    let tail = existing.get(after..).unwrap_or_default();
    let tail = tail.strip_prefix('\n').unwrap_or(tail);
    let head = existing.get(..start).unwrap_or_default();
    Ok(format!("{head}{BLOCK}{tail}"))
}

/// Resolves which file `ido add` writes.
///
/// # Errors
///
/// Refuses a relative path that leaves `cwd`, and a file name that is not an
/// agent instruction file.
pub fn target(path: Option<&Path>, cwd: &Path) -> Result<PathBuf, IdoError> {
    let chosen = match path {
        None => cwd.join("AGENTS.md"),
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => {
            if p.components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
            {
                return Err(IdoError::Refused(format!(
                    "{} leaves the current directory; give an absolute path if you mean it",
                    p.display()
                )));
            }
            cwd.join(p)
        }
    };
    let chosen = if chosen.is_dir() {
        chosen.join("AGENTS.md")
    } else {
        chosen
    };
    let name = chosen.file_name().unwrap_or_default();
    if !RECOGNISED.iter().any(|r| OsStr::new(r) == name) {
        return Err(IdoError::Refused(format!(
            "{} is not an agent instruction file; ido add writes one of: {}",
            chosen.display(),
            RECOGNISED.join(", ")
        )));
    }
    Ok(chosen)
}

/// Writes the block into `file`.
///
/// # Errors
///
/// Refuses a symlink and a file that is not UTF-8 or has malformed markers;
/// reports any I/O failure. On error the original file is untouched.
pub fn add(file: &Path) -> Result<Added, IdoError> {
    let existing = match std::fs::symlink_metadata(file) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(IdoError::Refused(format!(
                "{} is a symlink; ido add writes the file itself, never through a link",
                file.display()
            )));
        }
        Ok(meta) => Some((
            std::fs::read(file).map_err(|e| io("read", file, e))?,
            meta.permissions(),
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(io("inspect", file, e)),
    };

    let Some((bytes, permissions)) = existing else {
        write_atomically(file, BLOCK, None)?;
        return Ok(Added::Created(file.to_path_buf()));
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        IdoError::Refused(format!(
            "{} is not UTF-8; ido add will not rewrite it",
            file.display()
        ))
    })?;
    let updated = splice(&text)?;
    if updated == text {
        return Ok(Added::Unchanged(file.to_path_buf()));
    }
    backup_once(file, &text)?;
    write_atomically(file, &updated, Some(permissions))?;
    Ok(Added::Updated(file.to_path_buf()))
}

/// Copies the original aside the first time `ido add` changes a file.
fn backup_once(file: &Path, original: &str) -> Result<(), IdoError> {
    let mut name = file.as_os_str().to_owned();
    name.push(".ido-backup");
    let backup = PathBuf::from(name);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
    {
        // An existing backup is the *first* original; keep it.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        created => created
            .and_then(|mut out| {
                out.write_all(original.as_bytes())
                    .and_then(|()| out.sync_all())
            })
            .map_err(|e| io("back up", &backup, e)),
    }
}

/// Writes `contents` to a temporary file beside `file`, syncs it, and renames
/// it into place.
fn write_atomically(
    file: &Path,
    contents: &str,
    permissions: Option<std::fs::Permissions>,
) -> Result<(), IdoError> {
    let mut name = file.as_os_str().to_owned();
    name.push(format!(".ido-tmp.{}", std::process::id()));
    let tmp = PathBuf::from(name);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| io("create", &tmp, e))?;
    let written = out
        .write_all(contents.as_bytes())
        .and_then(|()| out.sync_all())
        .and_then(|()| permissions.map_or(Ok(()), |p| out.set_permissions(p)));
    drop(out);
    let renamed = written.and_then(|()| std::fs::rename(&tmp, file));
    renamed.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io("write", file, e)
    })
}

fn io(op: &'static str, path: &Path, source: std::io::Error) -> IdoError {
    IdoError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("ido-add-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_block_is_short_and_carries_both_markers() {
        assert!(BLOCK.starts_with(BEGIN));
        assert!(BLOCK.trim_end().ends_with(END));
        assert!(
            BLOCK.lines().count() < 30,
            "a long block gets summarised away"
        );
    }

    #[test]
    fn ido_add_preserves_surrounding_content() {
        let before = "# Project\n\nIntro.\n\n";
        let after = "\n## Later\n\nOutro, no newline";
        let old = format!("{before}<!-- ido:begin v0 -->\nold text\n{END}{after}");
        let new = splice(&old).unwrap();
        assert!(new.starts_with(before), "{new}");
        assert!(new.ends_with(after), "{new}");
        assert!(new.contains(BLOCK));
        assert!(!new.contains("old text"));
    }

    #[test]
    fn ido_add_is_idempotent() {
        let once = splice("# Notes\n").unwrap();
        let twice = splice(&once).unwrap();
        assert_eq!(once, twice);
        assert_eq!(once.matches(BEGIN).count(), 1);
        assert_eq!(once, format!("# Notes\n\n{BLOCK}"));
    }

    #[test]
    fn appending_separates_from_text_without_a_final_newline() {
        assert_eq!(splice("x").unwrap(), format!("x\n\n{BLOCK}"));
        assert_eq!(splice("").unwrap(), BLOCK);
    }

    #[test]
    fn markers_that_do_not_pair_up_are_refused() {
        for bad in [
            format!("{BEGIN}\nno end"),
            format!("{END}\nno begin"),
            format!("{END}\n{BEGIN}\n"),
            format!("{BLOCK}{BLOCK}"),
        ] {
            let err = splice(&bad).unwrap_err();
            assert!(err.to_string().contains("do not pair up"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn the_default_target_is_agents_md_here() {
        let cwd = scratch("default");
        assert_eq!(target(None, &cwd).unwrap(), cwd.join("AGENTS.md"));
        // A directory means the AGENTS.md inside it.
        std::fs::create_dir_all(cwd.join("sub")).unwrap();
        assert_eq!(
            target(Some(Path::new("./sub")), &cwd).unwrap(),
            cwd.join("./sub").join("AGENTS.md")
        );
    }

    #[test]
    fn a_relative_path_cannot_leave_the_current_directory() {
        let cwd = scratch("escape");
        for escape in ["../AGENTS.md", "sub/../../CLAUDE.md"] {
            let err = target(Some(Path::new(escape)), &cwd).unwrap_err();
            assert!(err.to_string().contains("absolute path"), "{escape}: {err}");
        }
        // An absolute path is a deliberate choice and is honoured.
        let absolute = cwd.join("CLAUDE.md");
        assert_eq!(target(Some(&absolute), &cwd).unwrap(), absolute);
    }

    #[test]
    fn only_agent_instruction_files_are_written() {
        let cwd = scratch("names");
        for name in RECOGNISED {
            assert!(target(Some(Path::new(name)), &cwd).is_ok(), "{name}");
        }
        let err = target(Some(Path::new(".bashrc")), &cwd).unwrap_err();
        assert!(
            err.to_string().contains("not an agent instruction file"),
            "{err}"
        );
        let err = target(Some(&cwd.join("notes.txt")), &cwd).unwrap_err();
        assert!(
            err.to_string().contains("not an agent instruction file"),
            "{err}"
        );
    }

    #[test]
    fn add_creates_then_updates_then_leaves_alone() {
        let dir = scratch("cycle");
        let file = dir.join("AGENTS.md");
        assert_eq!(add(&file).unwrap(), Added::Created(file.clone()));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), BLOCK);
        assert_eq!(add(&file).unwrap(), Added::Unchanged(file.clone()));
        assert!(
            !dir.join("AGENTS.md.ido-backup").exists(),
            "nothing changed"
        );
    }

    #[test]
    fn the_first_original_is_backed_up_and_kept() {
        let dir = scratch("backup");
        let file = dir.join("CLAUDE.md");
        std::fs::write(&file, "# Mine\n").unwrap();
        assert_eq!(add(&file).unwrap(), Added::Updated(file.clone()));
        let backup = dir.join("CLAUDE.md.ido-backup");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "# Mine\n");
        // A later change keeps the *first* original.
        std::fs::write(&file, "# Edited\n").unwrap();
        add(&file).unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "# Mine\n");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("# Edited\n\n{BLOCK}")
        );
        // No temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.contains("ido-tmp"))
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_symlink_is_refused_not_followed() {
        let dir = scratch("symlink");
        let real = dir.join("real.md");
        std::fs::write(&real, "x").unwrap();
        let link = dir.join("AGENTS.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = add(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "x");
    }

    #[test]
    fn a_non_utf8_file_is_refused_untouched() {
        let dir = scratch("binary");
        let file = dir.join("AGENTS.md");
        std::fs::write(&file, [0xFF, 0xFE]).unwrap();
        let err = add(&file).unwrap_err();
        assert!(err.to_string().contains("not UTF-8"), "{err}");
        assert_eq!(std::fs::read(&file).unwrap(), [0xFF, 0xFE]);
    }

    #[test]
    fn io_failures_name_the_path_and_leave_nothing_behind() {
        let dir = scratch("io");
        // Inspecting through a file used as a directory fails with ENOTDIR.
        std::fs::write(dir.join("plain"), "").unwrap();
        let err = add(&dir.join("plain").join("AGENTS.md")).unwrap_err();
        assert!(err.to_string().starts_with("inspect"), "{err}");

        // A directory where the file should be cannot be read.
        std::fs::create_dir_all(dir.join("AGENTS.md")).unwrap();
        let err = add(&dir.join("AGENTS.md")).unwrap_err();
        assert!(err.to_string().starts_with("read"), "{err}");

        // A blocked temporary path fails the create.
        let file = dir.join("CLAUDE.md");
        let mut tmp = file.as_os_str().to_owned();
        tmp.push(format!(".ido-tmp.{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let err = add(&file).unwrap_err();
        assert!(err.to_string().starts_with("create"), "{err}");

        // A blocked backup path fails the backup, before anything is written.
        let gemini = dir.join("GEMINI.md");
        std::fs::write(&gemini, "keep\n").unwrap();
        std::fs::create_dir_all(dir.join("GEMINI.md.ido-backup").join("x")).unwrap();
        // The backup path exists (as a directory), so it counts as kept.
        assert!(add(&gemini).is_ok());

        // A rename onto a non-empty directory fails, and the temp is removed.
        let target = dir.join("sub");
        std::fs::create_dir_all(target.join("AGENTS.md").join("inner")).unwrap();
        let err = write_atomically(&target.join("AGENTS.md"), "x", None).unwrap_err();
        assert!(err.to_string().starts_with("write"), "{err}");
        let mut tmp = target.join("AGENTS.md").as_os_str().to_owned();
        tmp.push(format!(".ido-tmp.{}", std::process::id()));
        assert!(!PathBuf::from(tmp).exists());
    }

    #[test]
    fn add_stops_at_the_first_failure_and_leaves_the_file_alone() {
        use std::os::unix::fs::PermissionsExt;

        // Markers that do not pair up.
        let dir = scratch("add-malformed");
        let file = dir.join("AGENTS.md");
        let malformed = format!("{BEGIN}\nno end\n");
        std::fs::write(&file, &malformed).unwrap();
        assert!(
            add(&file)
                .unwrap_err()
                .to_string()
                .contains("do not pair up")
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), malformed);

        // The backup is taken, then the temporary file cannot be created.
        let dir = scratch("add-tmp-blocked");
        let file = dir.join("AGENTS.md");
        std::fs::write(&file, "# mine\n").unwrap();
        let mut tmp = file.as_os_str().to_owned();
        tmp.push(format!(".ido-tmp.{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(add(&file).unwrap_err().to_string().starts_with("create"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "# mine\n");

        // The directory cannot take a backup. Root ignores modes, so the
        // refusal is only observable without it.
        let dir = scratch("add-readonly");
        let file = dir.join("AGENTS.md");
        std::fs::write(&file, "# mine\n").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Whether the kernel enforces the mode for this process at all: it
        // does not for root.
        let enforced = std::fs::write(dir.join("probe"), "").is_err();
        let outcome = add(&file);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let refused = outcome.is_err_and(|e| e.to_string().starts_with("back up"));
        let unchanged = std::fs::read_to_string(&file).unwrap() == "# mine\n";
        assert!(
            !enforced || (refused && unchanged),
            "a read-only directory must refuse the backup and leave the file alone"
        );
    }

    #[test]
    fn a_backup_that_cannot_be_created_is_an_error() {
        let dir = scratch("backup-fail");
        let err = backup_once(&dir.join("missing").join("AGENTS.md"), "x").unwrap_err();
        assert!(err.to_string().starts_with("back up"), "{err}");
    }
}
