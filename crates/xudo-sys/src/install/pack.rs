//! Installing and removing a rule pack as root: the step after sudo's prompt.
//!
//! `xudo rules add` first judges a pack as the operator, unprivileged, and
//! prints what changes and the pack's SHA-256. Only that digest, handed back
//! through sudo, lets this side write. Here, as root, every check is made again
//! from root's own reading of `/etc/xudo`, through the same trusted descriptors
//! `enrol` uses, immediately before the rename:
//!
//! * **Not from an agent's box.** A process inside `xudo.slice` (an enrolled
//!   harness unit or an agent scope) is refused, from the kernel's own
//!   `/proc/self/cgroup`. An enrolled account also has no password, so sudo
//!   cannot be its way here; this is the second wall.
//! * **The bytes the operator reviewed.** A pack whose digest is not the
//!   reviewed one was changed after the review, and is refused.
//! * **[`xudo_policy::pack::review`] again**, on the rules as root reads them
//!   now, with the pack's file as it will be written (marker included).
//! * **Never an operator's file.** The pack lands at `pack-<name>.toml` by an
//!   atomic rename that refuses to replace a file without xudo's marker, and
//!   `remove` deletes only a file with it.
//!
//! Nothing here fetches, and nothing updates by itself.

use xudo_backend::enrol::{MANAGED_MARKER, REGISTRY_DIR};
use xudo_policy::pack::{PackRefusal, Review, digest, file_name, header_of, review};
use xudo_policy::{HarnessFile, RuleFile, is_rule_file_name, valid_harness_label};

use super::enrol::EnrolOps;
use super::{InstallError, InstallOps};

/// Where rule files live.
pub const RULES_DIR: &str = "/etc/xudo/rules.d";

/// The kernel's account of this process's cgroup.
pub const OWN_CGROUP: &str = "/proc/self/cgroup";

/// The mode of an installed pack: root writes it, everyone may read the rules.
const PACK_MODE: u32 = 0o644;

/// The most bytes a pack may have.
pub const MAX_PACK_BYTES: usize = 1 << 20;

/// What `xudo rules add` hands the root side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackRequest {
    /// The pack, as root read it.
    pub bytes: Vec<u8>,
    /// The SHA-256 the operator reviewed, as hex.
    pub reviewed: String,
}

/// What a pack install or removal did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackReport {
    /// The file written or removed.
    pub path: String,
    /// What changed.
    pub review: Review,
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
    /// The pack is not the one reviewed.
    #[error(
        "the pack changed after it was reviewed (reviewed sha256 {reviewed}, now {found}); run \
         `xudo rules add` as yourself again and review it; nothing was changed"
    )]
    Changed {
        /// What the operator reviewed.
        reviewed: String,
        /// What root read.
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

/// Refuses a process whose cgroup is under `xudo.slice`, or cannot be read.
fn outside_agent_box(cgroup: std::io::Result<Vec<u8>>) -> Result<(), PackError> {
    let bytes = cgroup.map_err(|error| PackError::CgroupUnknown(error.to_string()))?;
    let paths: Vec<&[u8]> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        // `hierarchy:controllers:path`; a line without two colons is no path.
        .map(|line| line.splitn(3, |byte| *byte == b':').nth(2).unwrap_or(b""))
        .collect();
    if paths.is_empty() || paths.iter().any(|path| !path.starts_with(b"/")) {
        return Err(PackError::CgroupUnknown(format!(
            "{OWN_CGROUP} is not a cgroup list"
        )));
    }
    if paths
        .iter()
        .any(|path| *path == b"/xudo.slice" || path.starts_with(b"/xudo.slice/"))
    {
        Err(PackError::AgentBox)
    } else {
        Ok(())
    }
}

fn root_outside_box(
    ops: &dyn InstallOps,
    cgroup: std::io::Result<Vec<u8>>,
) -> Result<(), PackError> {
    match ops.effective_uid() {
        0 => outside_agent_box(cgroup),
        uid => Err(PackError::NotRoot { uid }),
    }
}

/// The rule files in `/etc/xudo/rules.d`, read through trusted descriptors.
fn rule_files(host: &dyn EnrolOps) -> Result<Vec<RuleFile>, PackError> {
    let names = host
        .list_dir(RULES_DIR)?
        .ok_or_else(|| InstallError::Missing {
            path: RULES_DIR.to_owned(),
        })?;
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

/// A pack's bytes as installed: xudo's marker line, then the pack unchanged.
pub fn installed_bytes(pack: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{MANAGED_MARKER} Installed by `xudo rules add`; remove it with `xudo rules remove`.\n"
    )
    .into_bytes();
    bytes.extend_from_slice(pack);
    bytes
}

/// Whether a file is one `rules add` wrote.
fn ours(bytes: &[u8]) -> bool {
    bytes.starts_with(MANAGED_MARKER.as_bytes())
}

/// Checks a pack again as root and renames it into place.
///
/// `cgroup` is this process's `/proc/self/cgroup`, as read.
///
/// # Errors
///
/// Any [`PackError`]; nothing is left changed.
pub fn add_pack(
    request: &PackRequest,
    cgroup: std::io::Result<Vec<u8>>,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<PackReport, PackError> {
    root_outside_box(ops, cgroup)?;
    let found = digest(&request.bytes);
    if found != request.reviewed {
        return Err(PackError::Changed {
            reviewed: request.reviewed.clone(),
            found,
        });
    }
    let name = header_of(&request.bytes)?.file_name();
    let path = format!("{RULES_DIR}/{name}");
    let before = rule_files(host)?;
    if let Some(existing) = before.iter().find(|file| file.name == name.as_bytes()) {
        if !ours(&existing.bytes) {
            return Err(InstallError::NotOurs {
                path,
                reason: "it does not begin with xudo's marker".to_owned(),
            }
            .into());
        }
    }
    let contents = installed_bytes(&request.bytes);
    let after: Vec<RuleFile> = before
        .iter()
        .filter(|file| file.name != name.as_bytes())
        .cloned()
        .chain(std::iter::once(RuleFile {
            name: name.clone().into_bytes(),
            bytes: contents.clone(),
        }))
        .collect();
    let review = review(before, after, &registry(host))?;
    let candidate = format!("{path}.candidate");
    let identity = ops.write_candidate(&candidate, &contents, PACK_MODE)?;
    if let Err(error) = ops.install(&candidate, &path, identity) {
        let _ = ops.discard(&candidate, identity);
        return Err(error.into());
    }
    Ok(PackReport { path, review })
}

/// Removes a pack `rules add` installed, if the rules without it still pass.
///
/// # Errors
///
/// [`PackError::NotInstalled`] for a name with no file of xudo's, and any
/// other [`PackError`]; nothing is left changed.
pub fn remove_pack(
    name: &str,
    cgroup: std::io::Result<Vec<u8>>,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<PackReport, PackError> {
    root_outside_box(ops, cgroup)?;
    let not_installed = || PackError::NotInstalled(name.to_owned());
    if !valid_harness_label(name) {
        return Err(not_installed());
    }
    let file = file_name(name);
    let path = format!("{RULES_DIR}/{file}");
    let before = rule_files(host)?;
    if !before
        .iter()
        .any(|found| found.name == file.as_bytes() && ours(&found.bytes))
    {
        return Err(not_installed());
    }
    let after: Vec<RuleFile> = before
        .iter()
        .filter(|found| found.name != file.as_bytes())
        .cloned()
        .collect();
    let review = review(before, after, &registry(host))?;
    ops.remove_managed(&path)?;
    Ok(PackReport { path, review })
}

#[cfg(test)]
mod tests;
