//! Where configuration and state live.
//!
//! Two very different answers, because only one of the binaries sits on a
//! privilege boundary.
//!
//! * **`aido`** reads root-owned paths under `/etc/aido` and has **no user
//!   layer at all**. A file the user can write is a file the agent can write, so
//!   `~/.config/aido` does not exist and must never be read.
//! * **`ido`** follows the XDG Base Directory specification. It crosses no
//!   privilege boundary — it runs as the user, with the user's own credentials,
//!   and nothing executes without the user selecting it — so there is no reason
//!   to restrict what a user configures about their own picker.
//!
//! # Never `/tmp`
//!
//! A predictable path in a world-writable directory is a symlink race, and this
//! project's own deny-list forbids it. `$XDG_RUNTIME_DIR` is frequently unset
//! over SSH; when it is, the fallback is a `0700` directory under state, and
//! [`XdgPaths::runtime_is_fallback`] says so rather than choosing `/tmp`
//! quietly.
//!
//! # Pure
//!
//! Nothing here reads the environment. The values are handed in, because
//! `std::env::var` is banned in this project's privileged crates for the reason
//! given in `CLAUDE.md`, and because a path resolver that reads its own inputs
//! cannot be tested against the cases that matter.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The root-owned paths `aido` reads. No user layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemPaths {
    /// `/etc/aido`.
    pub etc: PathBuf,
    /// `/var/lib/aido`.
    pub state: PathBuf,
    /// `/run/aido`.
    pub runtime: PathBuf,
    /// `/var/log/aido`.
    pub log: PathBuf,
}

impl Default for SystemPaths {
    fn default() -> Self {
        Self {
            etc: PathBuf::from("/etc/aido"),
            state: PathBuf::from("/var/lib/aido"),
            runtime: PathBuf::from("/run/aido"),
            log: PathBuf::from("/var/log/aido"),
        }
    }
}

impl SystemPaths {
    /// The global settings file.
    pub fn config(&self) -> PathBuf {
        self.etc.join("config.toml")
    }

    /// The rule drop-in directory.
    pub fn rules_dir(&self) -> PathBuf {
        self.etc.join("rules.d")
    }

    /// The `trust.d` directory: the only thing that may narrow the confirmation
    /// requirement.
    pub fn trust_dir(&self) -> PathBuf {
        self.etc.join("trust.d")
    }

    /// Every path that must be root-owned and not group- or world-writable.
    ///
    /// Enumerated here so the ownership check in `aido-sys` has one list to walk
    /// rather than a set of literals scattered across call sites.
    pub fn must_be_root_owned(&self) -> Vec<PathBuf> {
        vec![
            self.etc.clone(),
            self.config(),
            self.rules_dir(),
            self.trust_dir(),
            self.state.clone(),
            self.runtime.clone(),
            self.log.clone(),
        ]
    }
}

/// The per-user paths `ido` uses, resolved from XDG values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdgPaths {
    /// `$XDG_CONFIG_HOME/ido`.
    pub config: PathBuf,
    /// `$XDG_STATE_HOME/ido`.
    pub state: PathBuf,
    /// `$XDG_CACHE_HOME/ido`.
    pub cache: PathBuf,
    /// `$XDG_RUNTIME_DIR/ido`, or a state fallback.
    pub runtime: PathBuf,
    /// Whether `runtime` is the fallback rather than a real runtime directory.
    ///
    /// Reported rather than hidden: `$XDG_RUNTIME_DIR` is routinely unset over
    /// SSH, and an operator debugging a stale lock deserves to know which
    /// directory is actually in use.
    pub runtime_is_fallback: bool,
}

impl XdgPaths {
    /// Resolves the paths from explicitly-supplied values.
    ///
    /// Every argument is the value of the corresponding variable, or `None` when
    /// it is unset. A value that is empty or relative is treated as unset, which
    /// is what the specification requires and what stops a relative
    /// `XDG_STATE_HOME` from resolving against whatever directory the process
    /// happens to be in.
    pub fn resolve(
        home: &Path,
        config_home: Option<&str>,
        state_home: Option<&str>,
        cache_home: Option<&str>,
        runtime_dir: Option<&str>,
    ) -> Self {
        let config = absolute_or(config_home, || home.join(".config")).join("ido");
        let state = absolute_or(state_home, || home.join(".local").join("state")).join("ido");
        let cache = absolute_or(cache_home, || home.join(".cache")).join("ido");

        let (runtime, runtime_is_fallback) = match absolute(runtime_dir) {
            Some(dir) => (dir.join("ido"), false),
            // Under state, never /tmp. A predictable path in a world-writable
            // directory is a symlink race.
            None => (state.join("runtime"), true),
        };

        Self {
            config,
            state,
            cache,
            runtime,
            runtime_is_fallback,
        }
    }

    /// The settings file.
    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// The queue of commands an agent has buffered for the human to run.
    ///
    /// Under *state*, not runtime: a queue that vanishes on logout loses exactly
    /// the work the human meant to come back to.
    pub fn queue_file(&self) -> PathBuf {
        self.state.join("queue.jsonl")
    }

    /// The hash-chained log of what was run.
    pub fn log_file(&self) -> PathBuf {
        self.state.join("log.jsonl")
    }

    /// The advisory lock. Ephemeral by design.
    pub fn lock_file(&self) -> PathBuf {
        self.runtime.join("lock")
    }

    /// Every path that must be mode `0600` or `0700` and owned by the user.
    pub fn must_be_private(&self) -> Vec<PathBuf> {
        vec![
            self.config.clone(),
            self.state.clone(),
            self.runtime.clone(),
            self.queue_file(),
            self.log_file(),
        ]
    }

    /// Whether any resolved path sits under `/tmp`.
    ///
    /// A guard that exists to be asserted in a test rather than trusted: if this
    /// ever returns `true`, the resolver has acquired a `/tmp` fallback.
    pub fn touches_tmp(&self) -> bool {
        [&self.config, &self.state, &self.cache, &self.runtime]
            .into_iter()
            .any(|p| p.starts_with("/tmp") || p.starts_with("/var/tmp"))
    }
}

/// An absolute path from a supplied value, or `None`.
fn absolute(value: Option<&str>) -> Option<PathBuf> {
    let raw = value?;
    let path = PathBuf::from(raw);
    // Empty or relative is "unset", per the specification. Anything else would
    // resolve against the process's working directory.
    if raw.is_empty() || !path.is_absolute() {
        return None;
    }
    Some(path)
}

/// An absolute path from a supplied value, or the fallback.
fn absolute_or(value: Option<&str>, fallback: impl FnOnce() -> PathBuf) -> PathBuf {
    absolute(value).unwrap_or_else(fallback)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/home/u")
    }

    #[test]
    fn the_system_paths_are_the_root_owned_ones() {
        let paths = SystemPaths::default();
        assert_eq!(paths.config(), PathBuf::from("/etc/aido/config.toml"));
        assert_eq!(paths.rules_dir(), PathBuf::from("/etc/aido/rules.d"));
        assert_eq!(paths.trust_dir(), PathBuf::from("/etc/aido/trust.d"));
        assert_eq!(paths.state, PathBuf::from("/var/lib/aido"));
        assert_eq!(paths.runtime, PathBuf::from("/run/aido"));
        assert_eq!(paths.log, PathBuf::from("/var/log/aido"));
    }

    #[test]
    fn there_is_no_user_layer_for_aido_anywhere_in_the_system_paths() {
        // A file the user can write is a file the agent can write, so
        // ~/.config/aido must not appear.
        let paths = SystemPaths::default();
        for path in paths.must_be_root_owned() {
            let rendered = path.display().to_string();
            assert!(rendered.starts_with('/'), "{rendered}");
            assert!(!rendered.contains("/home/"), "{rendered}");
            assert!(!rendered.contains(".config"), "{rendered}");
        }
    }

    #[test]
    fn every_path_needing_an_ownership_check_is_enumerated_once() {
        let paths = SystemPaths::default();
        let listed = paths.must_be_root_owned();
        for expected in [
            paths.etc.clone(),
            paths.config(),
            paths.rules_dir(),
            paths.trust_dir(),
            paths.state.clone(),
            paths.runtime.clone(),
            paths.log.clone(),
        ] {
            assert!(listed.contains(&expected), "{expected:?} is not checked");
        }
        assert!(!paths.must_be_root_owned().is_empty());
    }

    #[test]
    fn xdg_values_are_used_when_they_are_absolute() {
        let paths = XdgPaths::resolve(
            &home(),
            Some("/cfg"),
            Some("/st"),
            Some("/ca"),
            Some("/run/user/1000"),
        );
        assert_eq!(paths.config, PathBuf::from("/cfg/ido"));
        assert_eq!(paths.state, PathBuf::from("/st/ido"));
        assert_eq!(paths.cache, PathBuf::from("/ca/ido"));
        assert_eq!(paths.runtime, PathBuf::from("/run/user/1000/ido"));
        assert!(!paths.runtime_is_fallback);
    }

    #[test]
    fn the_documented_fallbacks_apply_when_a_value_is_unset() {
        let paths = XdgPaths::resolve(&home(), None, None, None, None);
        assert_eq!(paths.config, PathBuf::from("/home/u/.config/ido"));
        assert_eq!(paths.state, PathBuf::from("/home/u/.local/state/ido"));
        assert_eq!(paths.cache, PathBuf::from("/home/u/.cache/ido"));
    }

    #[test]
    fn an_empty_or_relative_value_is_treated_as_unset() {
        // Required by the specification, and it stops a relative value from
        // resolving against whatever directory the process happens to be in.
        for bad in [Some(""), Some("relative/path"), Some("./here")] {
            let paths = XdgPaths::resolve(&home(), bad, bad, bad, bad);
            assert_eq!(
                paths.config,
                PathBuf::from("/home/u/.config/ido"),
                "{bad:?}"
            );
            assert_eq!(
                paths.state,
                PathBuf::from("/home/u/.local/state/ido"),
                "{bad:?}"
            );
            assert!(paths.runtime_is_fallback, "{bad:?}");
        }
        assert!(absolute(None).is_none());
    }

    #[test]
    fn an_unset_runtime_dir_falls_back_under_state_and_says_so() {
        // $XDG_RUNTIME_DIR is routinely unset over SSH. The fallback is
        // reported rather than hidden, so an operator chasing a stale lock knows
        // which directory is in use.
        let paths = XdgPaths::resolve(&home(), None, None, None, None);
        assert!(paths.runtime_is_fallback);
        assert_eq!(
            paths.runtime,
            PathBuf::from("/home/u/.local/state/ido/runtime")
        );
        assert!(paths.runtime.starts_with(&paths.state));
    }

    #[test]
    fn nothing_ever_resolves_into_tmp() {
        // The guard exists to be asserted, not trusted.
        for runtime in [None, Some(""), Some("/run/user/1000")] {
            let paths = XdgPaths::resolve(&home(), None, None, None, runtime);
            assert!(!paths.touches_tmp(), "{paths:?}");
        }
        // And the guard actually detects the thing it is guarding against.
        let contrived = XdgPaths::resolve(&home(), Some("/tmp/cfg"), None, None, None);
        assert!(contrived.touches_tmp());
        let also = XdgPaths::resolve(&home(), None, None, None, Some("/var/tmp/x"));
        assert!(also.touches_tmp());
    }

    #[test]
    fn the_queue_lives_under_state_so_it_survives_a_logout() {
        // A queue that vanishes on logout loses exactly the work the human
        // meant to come back to.
        let paths = XdgPaths::resolve(&home(), None, None, None, Some("/run/user/1000"));
        assert_eq!(
            paths.queue_file(),
            PathBuf::from("/home/u/.local/state/ido/queue.jsonl")
        );
        assert!(!paths.queue_file().starts_with(&paths.runtime));
        assert_eq!(
            paths.log_file(),
            PathBuf::from("/home/u/.local/state/ido/log.jsonl")
        );
        // The lock is ephemeral, so it does live in runtime.
        assert!(paths.lock_file().starts_with(&paths.runtime));
        assert_eq!(
            paths.config_file(),
            PathBuf::from("/home/u/.config/ido/config.toml")
        );
    }

    #[test]
    fn every_private_path_is_enumerated_for_the_permission_check() {
        let paths = XdgPaths::resolve(&home(), None, None, None, None);
        let private = paths.must_be_private();
        assert!(private.contains(&paths.queue_file()));
        assert!(private.contains(&paths.log_file()));
        assert!(private.contains(&paths.state));
        // The cache is not private: it holds dry-run previews, not queue state.
        assert!(!private.contains(&paths.cache));
    }

    #[test]
    fn paths_round_trip_and_reject_unknown_keys() {
        let system = SystemPaths::default();
        let json = serde_json::to_string(&system).unwrap();
        assert_eq!(serde_json::from_str::<SystemPaths>(&json).unwrap(), system);
        assert!(
            serde_json::from_str::<SystemPaths>(&json.replace("\"etc\"", "\"home\":\"/\",\"etc\""))
                .is_err()
        );

        let xdg = XdgPaths::resolve(&home(), None, None, None, None);
        let json = serde_json::to_string(&xdg).unwrap();
        assert_eq!(serde_json::from_str::<XdgPaths>(&json).unwrap(), xdg);
        assert!(format!("{xdg:?}").contains("runtime_is_fallback"));
    }
}
