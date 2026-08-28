//! Walking the process tree, and collecting claims that carry no weight.
//!
//! Everything in this module produces [`Hint`]s. Nothing in it produces
//! authority. That distinction is the whole design, so it is worth stating in
//! the one place a future reader is most likely to forget it: a caller who
//! forges every value here gains nothing except a more convincing entry in the
//! audit log, because the classification these hints accompany is decided
//! elsewhere and, at this milestone, is always `Unattested`.

use aido_policy::{Hint, HintSource};
use bstr::ByteSlice;

use crate::error::SysError;
use crate::proc::{ProcStat, parse_stat};
use crate::source::ProcSource;

/// How far up the process tree to walk.
///
/// A bound rather than a cycle guard: a process tree cannot contain a cycle, but
/// it can be made arbitrarily deep, and walking it is work an unprivileged
/// caller should not be able to demand of a privileged service.
pub const MAX_ANCESTRY_DEPTH: usize = 64;

/// Environment variables that some agent harnesses set.
///
/// Verified present in a live Claude Code session on 2026-08-26. Listed here so
/// they can be *recorded*, never believed: each one is a variable any process
/// can export, so a match means only that someone wrote the variable.
pub const AGENT_ENV_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ID",
    "AI_AGENT",
    "CURSOR_TRACE_ID",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
    "AIDER_MODEL",
];

/// One process in an ancestry chain, pinned so pid reuse cannot fool a later
/// check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcRef {
    /// The process id.
    pub pid: u32,
    /// Its start time, which together with the pid is stable for its lifetime.
    pub starttime: u64,
    /// Its `comm`, for the audit record. Arbitrary bytes, sixteen at most.
    pub comm: Vec<u8>,
}

impl From<ProcStat> for ProcRef {
    fn from(stat: ProcStat) -> Self {
        Self {
            pid: stat.pid,
            starttime: stat.starttime,
            comm: stat.comm,
        }
    }
}

/// A chain from a process up towards pid 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ancestry {
    /// The chain, starting with the process itself.
    pub chain: Vec<ProcRef>,
    /// Whether the walk reached pid 1, or stopped early.
    ///
    /// It stops early routinely: a parent can exit mid-walk, and inside a pid
    /// namespace the visible root is not pid 1. An incomplete chain is
    /// therefore normal, and a caller must not treat completeness as a signal.
    pub reached_root: bool,
}

impl Ancestry {
    /// The process the walk started from.
    pub fn origin(&self) -> Option<&ProcRef> {
        self.chain.first()
    }

    /// How many processes are in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Renders the chain for an audit record, innermost first.
    pub fn describe(&self) -> String {
        let rendered: Vec<String> = self
            .chain
            .iter()
            .map(|p| format!("{}({})", p.comm.as_bstr(), p.pid))
            .collect();
        let joined = rendered.join(" <- ");
        if self.reached_root {
            joined
        } else {
            format!("{joined} <- ?")
        }
    }
}

/// Walks from `pid` towards pid 1.
///
/// Each hop is pinned as `(pid, starttime)`. Stops at pid 1, at a self-parenting
/// process (which is how a pid-namespace root presents), or at the depth bound.
///
/// # Errors
///
/// Returns [`SysError::Read`] if the starting process cannot be read at all, and
/// [`SysError::AncestryTooDeep`] if the chain exceeds [`MAX_ANCESTRY_DEPTH`]. A
/// hop that fails part-way through is **not** an error: the parent may simply
/// have exited, so the walk stops and reports `reached_root: false`.
pub fn ancestry(source: &dyn ProcSource, pid: u32, limit: usize) -> Result<Ancestry, SysError> {
    let mut chain: Vec<ProcRef> = Vec::new();
    let mut current = pid;
    let mut reached_root = false;

    loop {
        if chain.len() >= limit {
            return Err(SysError::AncestryTooDeep { limit });
        }
        let path = format!("{current}/stat");
        let bytes = match source.read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                // The first read must succeed; a later one failing just means
                // an ancestor exited, which is ordinary.
                if chain.is_empty() {
                    return Err(err);
                }
                break;
            }
        };
        let stat = parse_stat(&path, &bytes)?;
        let parent = stat.ppid;
        chain.push(ProcRef::from(stat));

        if parent == 0 || parent == current {
            // pid 1's parent is 0; a self-parenting process is a namespace root.
            reached_root = true;
            break;
        }
        if current == 1 {
            reached_root = true;
            break;
        }
        current = parent;
    }

    Ok(Ancestry {
        chain,
        reached_root,
    })
}

/// Collects every unauthenticated claim about `pid` that is worth recording.
///
/// Reads `comm`, `cmdline`, `environ`, and the resolved `exe`, plus whether a
/// controlling terminal is present. Missing files are skipped: a hint that
/// cannot be read is simply a hint that is absent, and absence is not an error
/// because none of this is required for a decision.
pub fn hints(source: &dyn ProcSource, pid: u32) -> Vec<Hint> {
    let mut out: Vec<Hint> = Vec::new();

    if let Ok(bytes) = source.read(&format!("{pid}/comm")) {
        out.push(Hint::new(
            HintSource::Comm,
            "comm",
            bytes.trim_ascii_end().as_bstr().to_string(),
        ));
    }

    if let Ok(bytes) = source.read(&format!("{pid}/cmdline")) {
        // NUL-delimited. Rendered with spaces for the record only; nothing
        // reconstructs an argv from this.
        let rendered = bytes
            .split_str("\0")
            .filter(|part| !part.is_empty())
            .map(|part| part.as_bstr().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        if !rendered.is_empty() {
            out.push(Hint::new(HintSource::Cmdline, "cmdline", rendered));
        }
    }

    if let Ok(bytes) = source.read(&format!("{pid}/environ")) {
        for marker in AGENT_ENV_MARKERS {
            if let Some(value) = env_value(&bytes, marker) {
                out.push(Hint::new(HintSource::Environment, *marker, value));
            }
        }
    }

    if let Ok(bytes) = source.read(&format!("{pid}/exe")) {
        out.push(Hint::new(
            HintSource::AncestorExe,
            "exe",
            bytes.as_bstr().to_string(),
        ));
    }

    // A missing controlling terminal is the measured signature of a command run
    // inside an agent's tool call. Recorded, and worth exactly nothing.
    let has_tty = source
        .read(&format!("{pid}/stat"))
        .ok()
        .and_then(|bytes| parse_stat("stat", &bytes).ok())
        .is_some();
    out.push(Hint::new(
        HintSource::ControllingTty,
        "stat-readable",
        has_tty.to_string(),
    ));

    out
}

/// Extracts one variable from a NUL-delimited `environ` blob.
fn env_value(environ: &[u8], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    environ
        .split_str("\0")
        .find_map(|entry| entry.strip_prefix(prefix.as_bytes()))
        .map(|value| value.as_bstr().to_string())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use crate::source::MapSource;

    /// Builds a stat line with the fields this module reads.
    fn stat(pid: u32, comm: &str, parent: u32, starttime: u64) -> String {
        let mut tail: Vec<String> = vec!["S".into(), parent.to_string()];
        for _ in 0..17 {
            tail.push("0".to_owned());
        }
        tail.push(starttime.to_string());
        format!("{pid} ({comm}) {}", tail.join(" "))
    }

    fn tree() -> MapSource {
        MapSource::new()
            .with("412/stat", stat(412, "bash", 411, 5000))
            .with("411/stat", stat(411, "claude", 410, 4000))
            .with("410/stat", stat(410, "systemd", 1, 3000))
            .with("1/stat", stat(1, "systemd", 0, 1))
    }

    #[test]
    fn a_walk_reaches_the_root_and_pins_every_hop() {
        let a = ancestry(&tree(), 412, MAX_ANCESTRY_DEPTH).unwrap();
        assert_eq!(a.len(), 4);
        assert!(!a.is_empty());
        assert!(a.reached_root);
        assert_eq!(a.origin().map(|p| p.pid), Some(412));
        // The pin: every hop carries a starttime, so a later check cannot be
        // fooled by pid reuse.
        assert_eq!(
            a.chain.iter().map(|p| p.starttime).collect::<Vec<_>>(),
            vec![5000, 4000, 3000, 1]
        );
        assert_eq!(
            a.describe(),
            "bash(412) <- claude(411) <- systemd(410) <- systemd(1)"
        );
    }

    #[test]
    fn a_parent_that_exited_mid_walk_is_not_an_error() {
        // Ordinary, not exceptional: processes exit. The walk stops and says so.
        let partial = MapSource::new()
            .with("412/stat", stat(412, "bash", 411, 5000))
            .with("411/stat", stat(411, "claude", 999, 4000));
        let a = ancestry(&partial, 412, MAX_ANCESTRY_DEPTH).unwrap();
        assert_eq!(a.len(), 2);
        assert!(!a.reached_root);
        assert!(a.describe().ends_with("<- ?"));
    }

    #[test]
    fn an_unreadable_starting_process_is_an_error() {
        let err = ancestry(&MapSource::new(), 412, MAX_ANCESTRY_DEPTH).unwrap_err();
        assert!(err.to_string().contains("cannot read"), "{err}");
    }

    #[test]
    fn a_malformed_stat_anywhere_in_the_chain_fails_closed() {
        let broken = MapSource::new()
            .with("412/stat", stat(412, "bash", 411, 5000))
            .with("411/stat", "garbage with no parens");
        let err = ancestry(&broken, 412, MAX_ANCESTRY_DEPTH).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    #[test]
    fn a_self_parenting_process_terminates_the_walk() {
        // How a pid-namespace root presents. Must not loop.
        let ns = MapSource::new().with("7/stat", stat(7, "init", 7, 10));
        let a = ancestry(&ns, 7, MAX_ANCESTRY_DEPTH).unwrap();
        assert_eq!(a.len(), 1);
        assert!(a.reached_root);
    }

    #[test]
    fn pid_one_terminates_the_walk_even_with_a_nonzero_parent() {
        let odd = MapSource::new()
            .with("1/stat", stat(1, "init", 5, 1))
            .with("5/stat", stat(5, "impossible", 0, 2));
        let a = ancestry(&odd, 1, MAX_ANCESTRY_DEPTH).unwrap();
        assert_eq!(a.len(), 1);
        assert!(a.reached_root);
    }

    #[test]
    fn a_deep_chain_is_refused_rather_than_walked() {
        // A hostile tree can be made arbitrarily deep. Walking it is work an
        // unprivileged caller must not be able to demand.
        let mut source = MapSource::new();
        for pid in 1..=200u32 {
            source = source.with(
                format!("{pid}/stat"),
                stat(pid, "deep", pid.saturating_sub(1), u64::from(pid)),
            );
        }
        // Walk from the deep end, so the bound is what stops it rather than
        // reaching pid 1.
        let err = ancestry(&source, 200, 8).unwrap_err();
        assert_eq!(err, SysError::AncestryTooDeep { limit: 8 });
        // And a limit above the real depth completes normally.
        let ok = ancestry(&source, 200, 512).unwrap();
        assert_eq!(ok.len(), 200);
        assert!(ok.reached_root);
    }

    #[test]
    fn hints_are_collected_from_every_available_source() {
        let mut environ = Vec::new();
        environ.extend_from_slice(b"PATH=/usr/bin\0CLAUDECODE=1\0AI_AGENT=claude\0");
        let source = tree()
            .with("412/comm", "bash\n")
            .with("412/cmdline", b"bash\0-lc\0id\0".to_vec())
            .with("412/environ", environ)
            .with("412/exe", "/usr/bin/bash");

        let collected = hints(&source, 412);
        let keys: Vec<&str> = collected.iter().map(|h| h.key.as_str()).collect();
        assert!(keys.contains(&"comm"));
        assert!(keys.contains(&"cmdline"));
        assert!(keys.contains(&"CLAUDECODE"));
        assert!(keys.contains(&"AI_AGENT"));
        assert!(keys.contains(&"exe"));
        assert!(keys.contains(&"stat-readable"));
        // A variable that is not a marker is not recorded.
        assert!(!keys.contains(&"PATH"));

        let comm = collected.iter().find(|h| h.key == "comm").unwrap();
        assert_eq!(comm.value, "bash", "trailing newline should be trimmed");
        let cmdline = collected.iter().find(|h| h.key == "cmdline").unwrap();
        assert_eq!(cmdline.value, "bash -lc id");
    }

    #[test]
    fn a_process_with_no_readable_hint_files_still_yields_a_record() {
        // Absence is not an error: none of this is required for a decision.
        let collected = hints(&MapSource::new(), 412);
        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected.first().map(|h| h.source),
            Some(HintSource::ControllingTty)
        );
        assert_eq!(collected.first().map(|h| h.value.as_str()), Some("false"));
    }

    #[test]
    fn an_empty_cmdline_is_omitted_rather_than_recorded_as_blank() {
        let source = MapSource::new().with("412/cmdline", b"\0\0".to_vec());
        let collected = hints(&source, 412);
        assert!(collected.iter().all(|h| h.key != "cmdline"));
    }

    #[test]
    fn hint_values_of_arbitrary_bytes_survive_rendering() {
        let source = MapSource::new()
            .with("412/comm", vec![0xff, 0xfe])
            .with("412/exe", vec![b'/', 0xff]);
        let collected = hints(&source, 412);
        assert!(collected.iter().any(|h| h.key == "comm"));
        assert!(collected.iter().any(|h| h.key == "exe"));
    }

    #[test]
    fn every_documented_env_marker_is_actually_looked_for() {
        // Guards against a marker being added to the list and never read.
        for marker in AGENT_ENV_MARKERS {
            let environ = format!("{marker}=yes\0");
            let source = MapSource::new().with("1/environ", environ.into_bytes());
            let collected = hints(&source, 1);
            assert!(
                collected
                    .iter()
                    .any(|h| h.key == *marker && h.value == "yes"),
                "{marker} is listed but not collected"
            );
        }
    }

    #[test]
    fn an_env_marker_that_is_a_prefix_of_another_is_not_confused() {
        // CLAUDECODE and CLAUDE_CODE_ENTRYPOINT share a prefix; matching must
        // be on the full `NAME=` form.
        let source = MapSource::new().with("1/environ", b"CLAUDE_CODE_ENTRYPOINT=cli\0".to_vec());
        let collected = hints(&source, 1);
        assert!(collected.iter().any(|h| h.key == "CLAUDE_CODE_ENTRYPOINT"));
        assert!(collected.iter().all(|h| h.key != "CLAUDECODE"));
    }

    #[test]
    fn env_value_extracts_only_an_exact_name_match() {
        let environ = b"XCLAUDECODE=1\0CLAUDECODE=7\0";
        assert_eq!(env_value(environ, "CLAUDECODE"), Some("7".to_owned()));
        assert_eq!(env_value(environ, "MISSING"), None);
        assert_eq!(env_value(b"EMPTY=\0", "EMPTY"), Some(String::new()));
    }

    #[test]
    fn a_proc_ref_is_built_from_a_stat_record() {
        let converted = ProcRef::from(ProcStat {
            pid: 5,
            comm: b"x".to_vec(),
            ppid: 4,
            starttime: 9,
        });
        assert_eq!(converted.pid, 5);
        assert_eq!(converted.starttime, 9);
        assert_eq!(converted.comm, b"x".to_vec());
        assert!(format!("{converted:?}").contains('5'));
    }

    #[test]
    fn an_empty_ancestry_describes_as_empty() {
        let empty = Ancestry {
            chain: Vec::new(),
            reached_root: true,
        };
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.origin().is_none());
        assert_eq!(empty.describe(), "");
    }
}
