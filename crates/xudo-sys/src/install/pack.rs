//! Installing and removing a rule pack as root: the step after sudo's prompt.
//!
//! `xudo rules add` and `xudo rules remove` first judge the change as the
//! operator, unprivileged, and print what changes and a token. Only that
//! token, handed back through sudo, lets this side write. Here, as root, every
//! check is made again from root's own reading of `/etc/xudo`, through the same
//! trusted descriptors `enrol` uses, under a lock on the rules directory,
//! immediately before the rename:
//!
//! * **Not from an agent's box.** A process inside `xudo.slice` (an enrolled
//!   harness unit or an agent scope) is refused, from the kernel's own
//!   `/proc/<pid>/cgroup`, for this process and every ancestor below pid 1, so
//!   a `sudo` that PAM moved into a login session of its own is still caught
//!   by its parent. A process that double-forks and lets its parent die is
//!   reparented out of the chain, and `systemd-run --user` makes the user's
//!   manager the parent, so this is a hint, not the wall. So is the refusal of
//!   a cgroup namespace other than pid 1's, and of a bare `/` on the unified
//!   (`0::`) line, which says nothing about where the process is.
//! * **The wall is that an enrolled account has no password.** Run every
//!   harness as an account of its own (`xudo agent enrol`): it cannot answer
//!   sudo's prompt, so it never gets here. The sudoers drop-in sets
//!   `timestamp_timeout=0` for `/usr/bin/xudo`, which is only a speed bump: a
//!   harness that shares the human's account and terminal can still ride a
//!   warm sudo ticket through `sudo env xudo`, `sudo -s` or a copy of the
//!   binary. Give such a harness a terminal of its own, so the ticket (per
//!   terminal by default, `timestamp_type=tty`) is not the human's. A drop-in
//!   older than that line is reported, and does not block.
//! * **The change the operator reviewed.** The token binds the pack's bytes
//!   (or the name removed), `--allow-waivers`, and the generation of the rules
//!   and harness registry it was judged against. Root computes it again from
//!   its own reading; any difference refuses.
//! * **[`xudo_policy::pack::review`] again**, on the rules as root reads them
//!   now, with the pack's file as it will be written (marker included).
//! * **Never an operator's file.** The pack lands at `pack-<name>.toml` by an
//!   atomic rename that refuses to replace a file without the pack marker, and
//!   `remove` deletes only a file with it.
//!
//! Nothing here fetches, and nothing updates by itself.

use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use xudo_backend::enrol::REGISTRY_DIR;
use xudo_backend::snippet::{SUDOERS_PATH, XUDO_SELF_DEFAULTS, sets_self_timeout};
use xudo_policy::pack::{
    Change, PackRefusal, Review, file_name, header_of, installed_by_xudo, installed_bytes, review,
    with_pack, without_pack,
};
use xudo_policy::{HarnessFile, RuleFile, is_rule_file_name};

use super::enrol::EnrolOps;
use super::{InstallError, InstallOps};

/// Where rule files live.
pub const RULES_DIR: &str = "/etc/xudo/rules.d";

/// The most ancestors the walk visits before it gives up and refuses.
const MAX_ANCESTORS: usize = 4096;

/// The mode of an installed pack: root writes it, everyone may read the rules.
const PACK_MODE: u32 = 0o644;

/// The most bytes a pack may have.
pub const MAX_PACK_BYTES: usize = 1 << 20;

/// What `xudo rules add` hands the root side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackRequest {
    /// The pack, as root read it.
    pub bytes: Vec<u8>,
    /// The token the operator's review printed.
    pub reviewed: String,
    /// Whether the operator allowed `gtfobins-waiver` keys in the pack.
    pub allow_waivers: bool,
}

/// What a pack install or removal did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackReport {
    /// The file written or removed.
    pub path: String,
    /// What changed.
    pub review: Review,
    /// What the operator should fix, which did not block the change.
    pub warnings: Vec<String>,
}

/// Why a pack was not installed or removed. Nothing was changed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackError {
    /// Not root.
    #[error("this needs root (effective uid {uid}); nothing was changed")]
    NotRoot {
        /// The effective uid.
        uid: u32,
    },
    /// The process is inside an agent's box.
    #[error(
        "this runs inside xudo.slice, an agent's box: a harness cannot install or remove a rule \
         pack; nothing was changed"
    )]
    AgentBox,
    /// The process's cgroup could not be read.
    #[error("cannot tell whether this runs inside an agent's box ({0}); nothing was changed")]
    CgroupUnknown(String),
    /// The change is not the one reviewed.
    #[error(
        "this is not the change that was reviewed (token {reviewed}, now {found}): the pack, the \
         rules, the harness registry or --allow-waivers differ; review it again as yourself; \
         nothing was changed"
    )]
    Changed {
        /// The token the operator was shown.
        reviewed: String,
        /// The token of what root read.
        found: String,
    },
    /// The pack, or the rules with or without it, failed a check.
    #[error("{0}; nothing was changed")]
    Refused(#[from] PackRefusal),
    /// A file or directory step failed.
    #[error("{0}")]
    Install(#[from] InstallError),
    /// `remove` named a pack xudo did not install.
    #[error("{0} is not a pack xudo installed; nothing was changed")]
    NotInstalled(String),
}

/// Where this process runs, as `/proc` reports it: a seam, so the checks are
/// tested without a kernel.
pub trait Whereabouts {
    /// `/proc/<pid>/<file>`, read whole. `pid` is `self` or a number.
    ///
    /// # Errors
    ///
    /// Whatever the read returned.
    fn read(&self, pid: &str, file: &str) -> std::io::Result<Vec<u8>>;

    /// What `/proc/<pid>/ns/cgroup` links to.
    ///
    /// # Errors
    ///
    /// Whatever the read returned.
    fn cgroup_ns(&self, pid: &str) -> std::io::Result<Vec<u8>>;
}

/// The real `/proc`.
#[derive(Clone, Debug)]
pub struct HostWhereabouts {
    proc: PathBuf,
}

impl HostWhereabouts {
    /// The machine's own `/proc`.
    pub fn system() -> Self {
        Self::at(PathBuf::from("/proc"))
    }

    fn at(proc: PathBuf) -> Self {
        Self { proc }
    }
}

impl Whereabouts for HostWhereabouts {
    fn read(&self, pid: &str, file: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.proc.join(pid).join(file))
    }

    fn cgroup_ns(&self, pid: &str) -> std::io::Result<Vec<u8>> {
        let target = std::fs::read_link(self.proc.join(pid).join("ns").join("cgroup"))?;
        Ok(target.into_os_string().into_vec())
    }
}

/// Refuses one process's cgroup list when a line is under `xudo.slice`, and
/// when it says nothing: unreadable, empty, a line with no absolute path, or
/// a bare `/` on the unified `0::` line, which a cgroup namespace shows
/// whatever the real path is. A cgroup v1 line at `/` (`12:cpuset:/`) is
/// where most processes sit on a v1 or hybrid host, and says nothing either
/// way.
fn outside_slice(pid: &str, cgroup: std::io::Result<Vec<u8>>) -> Result<(), PackError> {
    let unknown = |why: String| PackError::CgroupUnknown(format!("/proc/{pid}/cgroup {why}"));
    let bytes = cgroup.map_err(|error| unknown(error.to_string()))?;
    let lines: Vec<(bool, &[u8])> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        // `hierarchy:controllers:path`; a line without two colons is no path.
        .map(|line| {
            let path = line.splitn(3, |byte| *byte == b':').nth(2).unwrap_or(b"");
            (line.starts_with(b"0::"), path)
        })
        .collect();
    if lines.is_empty()
        || lines
            .iter()
            .any(|(unified, path)| !path.starts_with(b"/") || (*unified && *path == b"/"))
    {
        return Err(unknown(
            "is not a list of cgroups below the root".to_owned(),
        ));
    }
    if lines
        .iter()
        .any(|(_, path)| *path == b"/xudo.slice" || path.starts_with(b"/xudo.slice/"))
    {
        Err(PackError::AgentBox)
    } else {
        Ok(())
    }
}

/// The parent pid in a `/proc/<pid>/status`.
fn parent_of(status: &[u8]) -> Option<u32> {
    let line = status
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"PPid:"))?;
    std::str::from_utf8(line).ok()?.trim().parse().ok()
}

/// Refuses a process that runs, or whose ancestor below pid 1 runs, inside
/// `xudo.slice`, or in a cgroup namespace other than pid 1's, or that cannot
/// tell. Pid 1 is never in the slice, and on a host without systemd it sits
/// at `/`, so its cgroup is not read.
fn outside_agent_box(at: &dyn Whereabouts) -> Result<(), PackError> {
    let ns = |pid: &str| {
        at.cgroup_ns(pid)
            .map_err(|error| PackError::CgroupUnknown(format!("/proc/{pid}/ns/cgroup: {error}")))
    };
    if ns("self")? != ns("1")? {
        return Err(PackError::CgroupUnknown(
            "this runs in a cgroup namespace of its own, which hides where it is".to_owned(),
        ));
    }
    let mut pid = "self".to_owned();
    for _ in 0..MAX_ANCESTORS {
        outside_slice(&pid, at.read(&pid, "cgroup"))?;
        let status = at
            .read(&pid, "status")
            .map_err(|error| PackError::CgroupUnknown(format!("/proc/{pid}/status: {error}")))?;
        match parent_of(&status) {
            Some(0 | 1) => return Ok(()),
            Some(parent) => pid = parent.to_string(),
            None => {
                return Err(PackError::CgroupUnknown(format!(
                    "/proc/{pid}/status names no parent"
                )));
            }
        }
    }
    Err(PackError::CgroupUnknown(format!(
        "the parent chain is longer than {MAX_ANCESTORS}"
    )))
}

fn root_outside_box(ops: &dyn InstallOps, at: &dyn Whereabouts) -> Result<(), PackError> {
    match ops.effective_uid() {
        0 => outside_agent_box(at),
        uid => Err(PackError::NotRoot { uid }),
    }
}

/// The rule files in `/etc/xudo/rules.d`, read through trusted descriptors.
///
/// Called under the directory's lock, which already refused a missing
/// directory. One removed since reads as empty: the review's token, bound to
/// the rules the operator saw, then refuses.
fn rule_files(host: &dyn EnrolOps) -> Result<Vec<RuleFile>, PackError> {
    let names = host.list_dir(RULES_DIR)?.unwrap_or_default();
    let mut files = Vec::new();
    for name in names
        .into_iter()
        .filter(|name| is_rule_file_name(name.as_bytes()))
    {
        let bytes = host.read_file(&format!("{RULES_DIR}/{name}"))?;
        files.extend(bytes.map(|bytes| RuleFile {
            name: name.into_bytes(),
            bytes,
        }));
    }
    Ok(files)
}

/// The registry as the loader takes it: a read that failed is a fault, which
/// [`review`] refuses, never an error that hides why.
fn registry(host: &dyn EnrolOps) -> Result<Vec<HarnessFile>, String> {
    let names = host
        .list_dir(REGISTRY_DIR)
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let mut files = Vec::new();
    for name in names
        .into_iter()
        .filter(|name| name.as_bytes().ends_with(b".toml"))
    {
        let path = format!("{REGISTRY_DIR}/{name}");
        let bytes = host.read_file(&path).map_err(|error| error.to_string())?;
        files.extend(bytes.map(|bytes| HarnessFile {
            name: name.into_bytes(),
            bytes,
        }));
    }
    Ok(files)
}

/// What the operator should know about the sudoers drop-in: nothing when it
/// sets [`XUDO_SELF_DEFAULTS`]. Never a refusal: the line is a speed bump.
fn drop_in_warnings(host: &dyn EnrolOps) -> Vec<String> {
    let why = match host.read_file(SUDOERS_PATH) {
        Ok(Some(bytes)) if sets_self_timeout(&bytes) => return Vec::new(),
        Ok(Some(_)) => "does not have".to_owned(),
        Ok(None) => "is not there, so it does not have".to_owned(),
        Err(error) => format!("cannot be read ({error}), so it may not have"),
    };
    vec![format!(
        "{SUDOERS_PATH} {why} `{XUDO_SELF_DEFAULTS}`, so a cached sudo credential can reach \
         `sudo xudo rules`; reinstall the sudoers drop-in with `sudo xudo install`"
    )]
}

/// Refuses a change whose token is not the one the operator was shown.
fn reviewed(review: &Review, token: &str) -> Result<(), PackError> {
    if review.token == token {
        Ok(())
    } else {
        Err(PackError::Changed {
            reviewed: token.to_owned(),
            found: review.token.clone(),
        })
    }
}

/// Checks a reviewed pack again as root and renames it into place.
///
/// `at` is where this process runs, as `/proc` reports it.
///
/// # Errors
///
/// Any [`PackError`]; nothing is left changed.
pub fn add_pack(
    request: &PackRequest,
    at: &dyn Whereabouts,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<PackReport, PackError> {
    root_outside_box(ops, at)?;
    let header = header_of(&request.bytes)?;
    let name = header.file_name();
    let path = format!("{RULES_DIR}/{name}");
    // Held until the rename: two runs cannot each judge without the other.
    let _lock = ops.lock_dir(RULES_DIR)?;
    let before = rule_files(host)?;
    if let Some(existing) = before.iter().find(|file| file.name == name.as_bytes()) {
        if !installed_by_xudo(&existing.bytes) {
            return Err(InstallError::NotOurs {
                path,
                reason: "it does not begin with xudo's rule-pack marker".to_owned(),
            }
            .into());
        }
    }
    let after = with_pack(&before, &header, &request.bytes);
    let change = Change::Add {
        pack: &request.bytes,
        allow_waivers: request.allow_waivers,
    };
    let review = review(before, after, &registry(host), change)?;
    reviewed(&review, &request.reviewed)?;
    let candidate = format!("{path}.candidate");
    let identity = ops.write_candidate(&candidate, &installed_bytes(&request.bytes), PACK_MODE)?;
    if let Err(error) = ops.install(&candidate, &path, identity) {
        let _ = ops.discard(&candidate, identity);
        return Err(error.into());
    }
    let warnings = drop_in_warnings(host);
    Ok(PackReport {
        path,
        review,
        warnings,
    })
}

/// Removes a pack `rules add` installed, if the rules without it still pass
/// and the change is the one reviewed.
///
/// # Errors
///
/// [`PackError::NotInstalled`] for a name with no file of xudo's, and any
/// other [`PackError`]; nothing is left changed.
pub fn remove_pack(
    name: &str,
    token: &str,
    at: &dyn Whereabouts,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<PackReport, PackError> {
    root_outside_box(ops, at)?;
    let _lock = ops.lock_dir(RULES_DIR)?;
    let before = rule_files(host)?;
    let after =
        without_pack(&before, name).ok_or_else(|| PackError::NotInstalled(name.to_owned()))?;
    let review = review(before, after, &registry(host), Change::Remove { name })?;
    reviewed(&review, token)?;
    let path = format!("{RULES_DIR}/{}", file_name(name));
    ops.remove_managed(&path)?;
    let warnings = drop_in_warnings(host);
    Ok(PackReport {
        path,
        review,
        warnings,
    })
}

#[cfg(test)]
mod tests;
