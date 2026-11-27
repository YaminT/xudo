//! `xudo install --agent-path`: the checks the front-end makes before it
//! hands the executor the opt-in plan.
//!
//! The plan itself is `xudo_backend::InstallPlan::with_agent_path`, and the
//! executor runs its refusal probe, edit checks and post-write checks. What is
//! decided here reads the machine: doas is refused; any other sudo or doas
//! line that names the agent group, xudo's aliases or its helpers stops the
//! install, as does a helper file or directory above it that is not root's
//! alone, and an account in the agent group that no harness in the registry
//! names; and the host's `kernel.yama.ptrace_scope` decides what
//! `--raise-ptrace-scope` writes (OD9 f-b). It never lowers a value and never
//! writes without the flag.

use std::io::Write;
use std::path::Path;

use xudo_backend::paths_to_root::{HostView, Lookup};
use xudo_backend::plan::AGENT_PATH_SUDO_ONLY;
use xudo_backend::snippet::{PTRACE_DROP_IN, PTRACE_DROP_IN_PATH, SUDOERS_PATH, names_agent_path};
use xudo_backend::{Backend, BackendKind, InstallPlan};
use xudo_policy::ExitCode;
use xudo_policy::harness::HarnessWay;

use crate::rules::{LoadError, LoadedRules};

/// Where the kernel reports the Yama ptrace setting.
pub(crate) const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Whether a session-way harness is registered: such a harness runs as the
/// human's uid, which is what a ptrace scope of 0 exposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionHarness {
    /// At least one.
    Registered,
    /// None: service-way harnesses only, or none at all.
    None,
    /// The registry could not be read, so nobody can say.
    Unknown(String),
}

/// What `--agent-path` needs from the harness registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Registry {
    /// Whether a session-way harness is registered.
    pub(crate) session: SessionHarness,
    /// Every account a harness names (a service account, or a user who may
    /// start a session), or why the registry could not be read.
    pub(crate) accounts: Result<Vec<String>, String>,
}

/// What the loaded rules say about the registry.
pub(crate) fn registry(loaded: Result<&LoadedRules, &LoadError>) -> Registry {
    let accounts = match loaded {
        Err(error) => Err(error.to_string()),
        Ok(rules) => match rules.registry_fault() {
            Some(fault) => Err(fault.to_owned()),
            None => Ok(rules
                .harnesses()
                .entries()
                .flat_map(|entry| entry.account.iter().chain(&entry.users))
                .cloned()
                .collect()),
        },
    };
    Registry {
        session: session_harness(loaded),
        accounts,
    }
}

/// What the loaded rules say about session-way harnesses.
pub(crate) fn session_harness(loaded: Result<&LoadedRules, &LoadError>) -> SessionHarness {
    match loaded {
        Err(error) => SessionHarness::Unknown(error.to_string()),
        Ok(rules) => match rules.registry_fault() {
            Some(fault) => SessionHarness::Unknown(fault.to_owned()),
            None if rules
                .harnesses()
                .entries()
                .any(|entry| entry.way == HarnessWay::Session) =>
            {
                SessionHarness::Registered
            }
            None => SessionHarness::None,
        },
    }
}

/// The live `kernel.yama.ptrace_scope`, or why it cannot be read.
pub(crate) fn ptrace_scope(host: &dyn HostView) -> Result<u8, String> {
    match host.read(Path::new(PTRACE_SCOPE)) {
        Lookup::Found(bytes) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or_else(|| format!("{PTRACE_SCOPE} does not hold a number")),
        Lookup::Missing => Err(format!(
            "{PTRACE_SCOPE} is missing: this kernel has no Yama"
        )),
        Lookup::Unreadable(why) => Err(format!("{PTRACE_SCOPE}: {why}")),
    }
}

/// Builds the opt-in plan, or says why not and returns the exit status.
///
/// `raise` is `--raise-ptrace-scope`. The drop-in is planned only when the
/// live value is 0: at 1 or more there is nothing to raise, and writing 1
/// over a higher value set at run time would lower it on `sysctl --system`.
pub(crate) fn plan(
    host: &dyn HostView,
    backend: &Backend,
    registry: &Registry,
    raise: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<InstallPlan, ExitCode> {
    if backend.kind == BackendKind::Doas {
        let _ = writeln!(err, "xudo: refusing --agent-path: {AGENT_PATH_SUDO_ONLY}");
        return Err(ExitCode::Unusable);
    }
    let session = &registry.session;
    let mut refusals = xudo_backend::agent_path::conflicts(host);
    refusals.extend(
        xudo_backend::agent_path::gate_faults(host)
            .into_iter()
            .map(|fault| format!("the passwordless helper cannot be trusted: {fault}")),
    );
    let member = match xudo_backend::agent_path::agent_members(host) {
        Err(why) => {
            refusals.push(format!("the members of xudo-agent cannot be known: {why}"));
            None
        }
        Ok(members) => {
            refusals.extend(unnamed(&members, &registry.accounts));
            members.into_iter().find(|name| is_plain_name(name))
        }
    };
    if !refusals.is_empty() {
        for refusal in &refusals {
            let _ = writeln!(err, "xudo: refusing --agent-path: {refusal}");
        }
        let _ = writeln!(
            err,
            "xudo: xudo's line must be the only one for the agent group, its aliases and its \
             helpers, the helper must be root's alone, and only registered accounts may be in \
             the agent group; fix each of these, then run the install again. Nothing was \
             written."
        );
        return Err(ExitCode::Unusable);
    }
    let raise = match (raise, ptrace_scope(host)) {
        (true, Ok(0)) => true,
        (true, Ok(now)) => {
            let _ = writeln!(
                out,
                "kernel.yama.ptrace_scope is already {now}: --raise-ptrace-scope writes nothing"
            );
            false
        }
        (true, Err(why)) => {
            let _ = writeln!(
                err,
                "xudo: refusing --raise-ptrace-scope: {why}. Nothing was written."
            );
            return Err(ExitCode::Unusable);
        }
        (false, Ok(0)) if *session != SessionHarness::None => {
            let _ = writeln!(
                err,
                "xudo: warning: kernel.yama.ptrace_scope is 0 here and a session-way harness \
                 is registered, or the registry could not be read. At 0 any process of the \
                 human's uid, an agent included, can attach to the human's terminal and read \
                 a password as it is typed. `sudo xudo install --agent-path \
                 --raise-ptrace-scope` writes {PTRACE_DROP_IN_PATH} setting it to 1."
            );
            false
        }
        (false, _) => false,
    };
    if raise {
        let _ = writeln!(out, "--- /dev/null\n+++ {PTRACE_DROP_IN_PATH}");
        for line in PTRACE_DROP_IN.lines() {
            let _ = writeln!(out, "+{line}");
        }
        let _ = writeln!(
            out,
            "xudo writes this file and does not apply it: it takes effect with \
             `sudo sysctl --system` or at boot, and only if no file read after it sets the \
             value too."
        );
        for setting in later_ptrace_settings(host) {
            let _ = writeln!(
                err,
                "xudo: warning: {setting}, so the drop-in does not decide the value and the \
                 scope may stay at 0"
            );
        }
    }
    agent_plan_for(backend, raise, member.as_deref()).map_err(|reason| {
        let _ = writeln!(err, "xudo: no usable backend: {reason}");
        ExitCode::Unusable
    })
}

/// The opt-in plan, with its failure as text. Detection refuses a backend
/// that cannot be given a snippet first, so only a test reaches the error.
fn agent_plan_for(
    backend: &Backend,
    raise: bool,
    member: Option<&str>,
) -> Result<InstallPlan, String> {
    InstallPlan::with_agent_path(backend, raise, member).map_err(|source| source.to_string())
}

/// One refusal per member of the agent group that no harness names. Only
/// `enrol` adds an account to the group; one that is in it otherwise reaches
/// the passwordless helper with no password, and nothing registered it.
fn unnamed(members: &[String], accounts: &Result<Vec<String>, String>) -> Vec<String> {
    members
        .iter()
        .filter_map(|member| match accounts {
            Ok(named) if named.contains(member) => None,
            Ok(_) => Some(format!(
                "{member} is in xudo-agent and no harness in the registry names it; only \
                 `xudo agent enrol` adds an account to that group"
            )),
            Err(why) => Some(format!(
                "{member} is in xudo-agent and the registry could not be read ({why}), so \
                 nothing shows the account belongs there"
            )),
        })
        .collect()
}

/// Whether `name` is safe to pass to the backend as a user name: one word
/// that cannot be read as an option.
fn is_plain_name(name: &str) -> bool {
    !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Where sysctl settings are read from, in systemd-sysctl's order of
/// precedence: a file in an earlier directory hides one of the same name in a
/// later one, and the files are applied in name order, the last one winning.
const SYSCTL_DIRS: [&str; 4] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
];

/// Every setting of `kernel.yama.ptrace_scope` read after xudo's drop-in: in
/// a `.conf` file whose name sorts after it, or in `/etc/sysctl.conf`, which
/// `sysctl --system` reads last. One entry per line, and one per file or
/// directory that could not be read. Warned about, never refused: such a line
/// only keeps the scope where it is.
fn later_ptrace_settings(host: &dyn HostView) -> Vec<String> {
    // `rsplit` always yields at least one part.
    let ours = PTRACE_DROP_IN_PATH.rsplit('/').next().unwrap_or_default();
    let mut files = Vec::new();
    let mut out = Vec::new();
    for dir in SYSCTL_DIRS {
        match host.list(Path::new(dir)) {
            Lookup::Found(names) => files.extend(
                names
                    .iter()
                    .filter(|name| {
                        let name = name.as_encoded_bytes();
                        name.ends_with(b".conf") && name > ours.as_bytes()
                    })
                    .map(|name| Path::new(dir).join(name)),
            ),
            Lookup::Missing => {}
            Lookup::Unreadable(why) => out.push(format!("{dir} could not be examined: {why}")),
        }
    }
    files.push(Path::new("/etc/sysctl.conf").to_path_buf());
    for file in files {
        match host.read(&file) {
            Lookup::Found(bytes) => {
                for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
                    let line = line.trim_ascii_start();
                    let comment = line.first().is_some_and(|byte| b"#;".contains(byte));
                    let names = [
                        &b"kernel.yama.ptrace_scope"[..],
                        b"kernel/yama/ptrace_scope",
                    ]
                    .iter()
                    .any(|key| line.windows(key.len()).any(|window| window == *key));
                    if names && !comment {
                        out.push(format!(
                            "{} line {} sets kernel.yama.ptrace_scope after xudo's drop-in",
                            file.display(),
                            index.saturating_add(1)
                        ));
                    }
                }
            }
            Lookup::Missing => {}
            Lookup::Unreadable(why) => {
                out.push(format!("{} could not be examined: {why}", file.display()));
            }
        }
    }
    out
}

/// Before a plain install: if the file there now names the agent path, say
/// that this install turns it off. A package upgrade runs a plain install.
pub(crate) fn warn_if_on(host: &dyn HostView, err: &mut dyn Write) {
    if let Lookup::Found(bytes) = host.read(Path::new(SUDOERS_PATH)) {
        if names_agent_path(&bytes) {
            let _ = writeln!(
                err,
                "xudo: warning: {SUDOERS_PATH} turns the agent path on; this install writes the \
                 human-only file and turns it off. `sudo xudo install --agent-path` turns it on \
                 again."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::path::PathBuf;

    use xudo_backend::paths_to_root::{Caller, MemoryHost};
    use xudo_backend::{Capability, CapabilityMatrix, PlanStep};

    use super::*;

    fn backend(kind: BackendKind) -> Backend {
        Backend {
            exe: kind.exe().to_owned(),
            kind,
            version: "test 1".to_owned(),
            capabilities: CapabilityMatrix::from_supported(Capability::ALL),
        }
    }

    /// A root-run host with a stock sudoers and `ptrace_scope` holding `scope`.
    fn host(scope: Option<&[u8]>) -> MemoryHost {
        let host = MemoryHost::new(Caller {
            uid: 0,
            gid: 0,
            groups: Lookup::Found(vec![0]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/group", 0, 0, 0o644, b"root:x:0:\nxudo-agent:x:997:\n")
        .file("/etc/passwd", 0, 0, 0o644, b"root:x:0:0::/root:/bin/sh\n")
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/libexec", 0, 0, 0o755)
        .dir("/usr/libexec/xudo", 0, 0, 0o755)
        .file(xudo_backend::snippet::GATE_NOPASS, 0, 0, 0o755, b"gate")
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
        )
        .dir("/etc/sudoers.d", 0, 0, 0o750)
        .dir("/proc", 0, 0, 0o555)
        .dir("/proc/sys", 0, 0, 0o555)
        .dir("/proc/sys/kernel", 0, 0, 0o555)
        .dir("/proc/sys/kernel/yama", 0, 0, 0o555);
        match scope {
            Some(bytes) => host.file(PTRACE_SCOPE, 0, 0, 0o644, bytes),
            None => host,
        }
    }

    /// `plan`, with what it printed, for a registry naming `agent`.
    fn planned(
        host: &MemoryHost,
        kind: BackendKind,
        session: &SessionHarness,
        raise: bool,
    ) -> (Result<InstallPlan, ExitCode>, String, String) {
        let registry = Registry {
            session: session.clone(),
            accounts: Ok(vec!["agent".to_owned()]),
        };
        planned_with(host, kind, &registry, raise)
    }

    fn planned_with(
        host: &MemoryHost,
        kind: BackendKind,
        registry: &Registry,
        raise: bool,
    ) -> (Result<InstallPlan, ExitCode>, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(host, &backend(kind), registry, raise, &mut out, &mut err);
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn writes_drop_in(plan: &InstallPlan) -> bool {
        plan.steps
            .iter()
            .any(|step| matches!(step, PlanStep::Install { to, .. } if to == PTRACE_DROP_IN_PATH))
    }

    #[test]
    fn the_agent_path_refuses_doas() {
        let (result, out, err) = planned(
            &host(Some(b"1\n")),
            BackendKind::Doas,
            &SessionHarness::None,
            false,
        );
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(err.contains("sudo and sudo-rs only"), "{err}");
        assert_eq!(out, "");
    }

    #[test]
    fn a_hand_written_agent_line_stops_the_install_and_names_it() {
        let host = host(Some(b"1\n")).file(
            "/etc/sudoers.d/00-ops",
            0,
            0,
            0o440,
            b"%xudo-agent ALL=(ALL) NOPASSWD: ALL\n",
        );
        let (result, _, err) = planned(&host, BackendKind::Sudo, &SessionHarness::None, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(err.contains("/etc/sudoers.d/00-ops line 1"), "{err}");
        assert!(err.contains("Nothing was written"), "{err}");
    }

    #[test]
    fn the_drop_in_is_raised_only_with_the_flag_and_only_from_zero() {
        // At 0 with the flag: planned, and the diff is printed first.
        let (result, out, _) = planned(
            &host(Some(b"0\n")),
            BackendKind::Sudo,
            &SessionHarness::None,
            true,
        );
        assert!(writes_drop_in(&result.unwrap()));
        assert!(
            out.contains("+++ /etc/sysctl.d/05-xudo-ptrace-scope.conf"),
            "{out}"
        );
        assert!(out.contains("+kernel.yama.ptrace_scope = 1"), "{out}");
        // At 0 without the flag: never written, whatever is registered.
        for session in [
            SessionHarness::Registered,
            SessionHarness::None,
            SessionHarness::Unknown("x".to_owned()),
        ] {
            let (result, _, _) = planned(&host(Some(b"0\n")), BackendKind::Sudo, &session, false);
            assert!(!writes_drop_in(&result.unwrap()), "{session:?}");
        }
    }

    #[test]
    fn the_drop_in_never_lowers_a_higher_value() {
        // 1, 2 or 3 is already at least what the drop-in sets: nothing written.
        for now in [&b"1\n"[..], b"2\n", b"3"] {
            let (result, out, _) = planned(
                &host(Some(now)),
                BackendKind::SudoRs,
                &SessionHarness::None,
                true,
            );
            assert!(!writes_drop_in(&result.unwrap()));
            assert!(out.contains("already"), "{out}");
        }
    }

    #[test]
    fn an_unreadable_ptrace_scope_refuses_the_flag_and_writes_nothing() {
        for host in [
            host(None),
            host(Some(b"zero\n")),
            host(Some(&[0xff])),
            host(None).unreadable_file(PTRACE_SCOPE, 0, 0, 0o600),
        ] {
            let (result, _, err) = planned(&host, BackendKind::Sudo, &SessionHarness::None, true);
            assert_eq!(result.unwrap_err(), ExitCode::Unusable);
            assert!(err.contains("Nothing was written"), "{err}");
            // Without the flag the same host still gets the agent path.
            let (result, _, _) = planned(&host, BackendKind::Sudo, &SessionHarness::None, false);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn a_session_harness_at_zero_is_told_the_flag_and_a_service_host_is_not() {
        for session in [
            SessionHarness::Registered,
            SessionHarness::Unknown("x".to_owned()),
        ] {
            let (_, _, err) = planned(&host(Some(b"0\n")), BackendKind::Sudo, &session, false);
            assert!(err.contains("--raise-ptrace-scope"), "{err}");
        }
        let (_, _, err) = planned(
            &host(Some(b"0\n")),
            BackendKind::Sudo,
            &SessionHarness::None,
            false,
        );
        assert_eq!(err, "");
        let (_, _, err) = planned(
            &host(Some(b"1\n")),
            BackendKind::Sudo,
            &SessionHarness::Registered,
            false,
        );
        assert_eq!(err, "");
    }

    #[test]
    fn a_backend_with_no_honest_snippet_gets_no_agent_plan() {
        let crippled = Backend {
            capabilities: CapabilityMatrix::empty(),
            ..backend(BackendKind::Sudo)
        };
        assert!(
            agent_plan_for(&crippled, false, None)
                .unwrap_err()
                .contains("cannot generate")
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &host(Some(b"1")),
            &crippled,
            &Registry {
                session: SessionHarness::None,
                accounts: Ok(Vec::new()),
            },
            false,
            &mut out,
            &mut err,
        );
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("no usable backend")
        );
    }

    #[test]
    fn a_plain_install_says_it_turns_the_agent_path_off() {
        let agent = xudo_backend::SudoersSnippet::with_agent_path(&backend(BackendKind::Sudo))
            .unwrap()
            .contents;
        let mut err = Vec::new();
        warn_if_on(
            &host(None).file(SUDOERS_PATH, 0, 0, 0o440, agent.as_bytes()),
            &mut err,
        );
        assert!(String::from_utf8(err).unwrap().contains("turns it off"));
        let human = xudo_backend::SudoersSnippet::human_only(&backend(BackendKind::Sudo))
            .unwrap()
            .contents;
        let mut err = Vec::new();
        warn_if_on(
            &host(None).file(SUDOERS_PATH, 0, 0, 0o440, human.as_bytes()),
            &mut err,
        );
        warn_if_on(&host(None), &mut err);
        assert!(err.is_empty());
    }

    /// A rules directory beside a `harnesses.d` holding `entries`.
    fn registry_dir(name: &str, entries: &[(&str, &str)]) -> PathBuf {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("agent-path-{name}"));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(parent.join("rules.d")).unwrap();
        std::fs::create_dir_all(parent.join("harnesses.d")).unwrap();
        for (file, text) in entries {
            std::fs::write(parent.join("harnesses.d").join(file), text).unwrap();
        }
        parent.join("rules.d")
    }

    #[test]
    fn a_session_way_entry_is_what_counts() {
        let service = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
        let session = "label = \"dev\"\nway = \"session\"\nusers = [\"carol\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n";
        let only_service =
            LoadedRules::from_dir(&registry_dir("service", &[("codex.toml", service)]));
        assert_eq!(session_harness(only_service.as_ref()), SessionHarness::None);
        let both = LoadedRules::from_dir(&registry_dir(
            "session",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        assert_eq!(session_harness(both.as_ref()), SessionHarness::Registered);
        let faulty = LoadedRules::from_dir(&registry_dir("fault", &[("x.toml", "wat = 1\n")]));
        assert!(format!("{:?}", session_harness(faulty.as_ref())).starts_with("Unknown("));
        let missing = LoadedRules::from_dir(Path::new("/xudo-test-no-such-rules"));
        assert!(format!("{:?}", session_harness(missing.as_ref())).starts_with("Unknown("));
    }

    #[test]
    fn a_helper_anyone_but_root_could_swap_stops_the_install() {
        let gate = xudo_backend::snippet::GATE_NOPASS;
        for host in [
            host(Some(b"1\n")).file(gate, 0, 1000, 0o775, b"gate"),
            host(Some(b"1\n")).dir("/usr/libexec/xudo", 1000, 1000, 0o755),
            host(Some(b"1\n")).hard_linked(gate),
        ] {
            let (result, out, err) =
                planned(&host, BackendKind::Sudo, &SessionHarness::None, false);
            assert_eq!(result.unwrap_err(), ExitCode::Unusable);
            assert!(
                err.contains("refusing --agent-path: the passwordless helper cannot be trusted"),
                "{err}"
            );
            assert!(err.contains("Nothing was written"), "{err}");
            assert_eq!(out, "");
        }
    }

    /// `host` with `group` as its agent-group line and an account `lurker`
    /// whose primary gid is 990.
    fn with_members(group: &[u8]) -> MemoryHost {
        host(Some(b"1\n"))
            .file("/etc/group", 0, 0, 0o644, group)
            .file(
                "/etc/passwd",
                0,
                0,
                0o644,
                b"agent:x:990:990::/:/bin/sh\nlurker:x:991:997::/:/bin/sh\n",
            )
    }

    fn listed_users(plan: &InstallPlan) -> Vec<String> {
        plan.steps
            .iter()
            .filter_map(|step| match step {
                PlanStep::MustNotList { argv, .. } => argv.get(4).cloned(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_unregistered_member_of_the_agent_group_stops_the_install_and_is_named() {
        // Listed in /etc/group, or in it by primary gid: either way it would
        // reach the passwordless helper, and no harness names it.
        for (group, who) in [
            (&b"xudo-agent:x:997:agent,mallory\n"[..], "mallory"),
            (b"xudo-agent:x:997:agent\nlurk:x:997:\n", "lurker"),
        ] {
            let host = with_members(group);
            let (result, _, err) = planned(&host, BackendKind::Sudo, &SessionHarness::None, false);
            assert_eq!(result.unwrap_err(), ExitCode::Unusable);
            assert!(
                err.contains(&format!(
                    "refusing --agent-path: {who} is in xudo-agent and no harness in the \
                     registry names it"
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn a_group_of_exactly_registered_accounts_is_accepted_and_asked_about() {
        let host = with_members(b"xudo-agent:x:996:agent\n");
        let (result, _, err) = planned(&host, BackendKind::Sudo, &SessionHarness::None, false);
        assert_eq!(listed_users(&result.unwrap()), ["nobody", "agent"], "{err}");
        // A registered name that could be read as an option is never passed
        // to the backend: nobody stands in.
        let odd = with_members(b"xudo-agent:x:996:-x\n");
        let registry = Registry {
            session: SessionHarness::None,
            accounts: Ok(vec!["-x".to_owned()]),
        };
        let (result, _, _) = planned_with(&odd, BackendKind::Sudo, &registry, false);
        assert_eq!(listed_users(&result.unwrap()), ["nobody", "nobody"]);
        assert!(is_plain_name("svc-agent.1_b"));
        assert!(!is_plain_name("a b"));
    }

    #[test]
    fn members_nobody_can_vouch_for_stop_the_install() {
        // The registry could not be read: no member can be shown to belong.
        let members = with_members(b"xudo-agent:x:996:agent\n");
        let unread = Registry {
            session: SessionHarness::Unknown("bad".to_owned()),
            accounts: Err("bad registry".to_owned()),
        };
        let (result, _, err) = planned_with(&members, BackendKind::Sudo, &unread, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("the registry could not be read (bad registry)"),
            "{err}"
        );
        // An empty group needs no registry.
        let (result, _, _) = planned_with(&host(Some(b"1\n")), BackendKind::Sudo, &unread, false);
        assert!(result.is_ok());
        // The group itself could not be read: the members cannot be known.
        let unreadable = host(Some(b"1\n")).unreadable_file("/etc/group", 0, 0, 0o600);
        let (result, _, err) =
            planned(&unreadable, BackendKind::Sudo, &SessionHarness::None, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("the members of xudo-agent cannot be known"),
            "{err}"
        );
    }

    #[test]
    fn a_later_sysctl_setting_is_named_and_the_drop_in_is_not_said_to_win() {
        let host = host(Some(b"0\n"))
            .dir("/etc/sysctl.d", 0, 0, 0o755)
            .file(
                "/etc/sysctl.d/10-ptrace.conf",
                0,
                0,
                0o644,
                b"# kernel.yama.ptrace_scope = 1\n; kernel.yama.ptrace_scope = 1\nkernel.yama.ptrace_scope = 0\n",
            )
            .file("/etc/sysctl.d/00-early.conf", 0, 0, 0o644, b"kernel.yama.ptrace_scope = 0\n")
            .file("/etc/sysctl.d/99-notes.txt", 0, 0, 0o644, b"kernel.yama.ptrace_scope = 0\n")
            .dir("/run", 0, 0, 0o755)
            .unlistable_dir("/run/sysctl.d", 0, 0, 0o711)
            .dir("/usr/lib", 0, 0, 0o755)
            .dir("/usr/lib/sysctl.d", 0, 0, 0o755)
            .file("/usr/lib/sysctl.d/50-x.conf", 0, 0, 0o644, b"kernel/yama/ptrace_scope=0\n")
            .unreadable_file("/usr/lib/sysctl.d/60-y.conf", 0, 0, 0o600)
            .file("/etc/sysctl.conf", 0, 0, 0o644, b"kernel.yama.ptrace_scope=0\n");
        let (result, out, err) = planned(&host, BackendKind::Sudo, &SessionHarness::None, true);
        assert!(writes_drop_in(&result.unwrap()));
        assert!(out.contains("does not apply it"), "{out}");
        assert!(!out.contains("next boot"), "{out}");
        for named in [
            "/etc/sysctl.d/10-ptrace.conf line 3 sets",
            "/usr/lib/sysctl.d/50-x.conf line 1 sets",
            "/usr/lib/sysctl.d/60-y.conf could not be examined",
            "/run/sysctl.d could not be examined",
            "/etc/sysctl.conf line 1 sets",
        ] {
            assert!(err.contains(named), "{named}: {err}");
        }
        assert!(!err.contains("00-early"), "{err}");
        assert!(!err.contains("99-notes"), "{err}");
        assert!(!err.contains("10-ptrace.conf line 1"), "{err}");
        assert!(!err.contains("10-ptrace.conf line 2"), "{err}");
    }

    #[test]
    fn every_account_a_harness_names_is_registered() {
        let service = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
        let session = "label = \"dev\"\nway = \"session\"\nusers = [\"carol\", \"dave\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n";
        let both = LoadedRules::from_dir(&registry_dir(
            "accounts",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        let mut accounts = registry(both.as_ref()).accounts.unwrap();
        accounts.sort();
        assert_eq!(accounts, ["agent", "carol", "dave"]);
        let faulty =
            LoadedRules::from_dir(&registry_dir("accounts-fault", &[("x.toml", "wat = 1\n")]));
        assert!(registry(faulty.as_ref()).accounts.is_err());
        let missing = LoadedRules::from_dir(Path::new("/xudo-test-no-such-rules"));
        assert!(registry(missing.as_ref()).accounts.is_err());
    }
}
