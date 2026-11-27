//! `xudo install --agent-path`: the checks the front-end makes before it
//! hands the executor the opt-in plan.
//!
//! The plan itself is `xudo_backend::InstallPlan::with_agent_path`, and the
//! executor runs its refusal probe, edit checks and post-write checks. What is
//! decided here reads the machine: doas is refused; any other sudo or doas
//! line that names the agent group, xudo's aliases or its helpers stops the
//! install, as does a helper file or directory above it that is not root's
//! alone, and an account in the agent group that no harness in the registry
//! names. The host's live `kernel.yama.ptrace_scope` must be 1 or more: at 0
//! a process of an enrolled agent's account outside its unit (an SSH key
//! login, a cron or at job, a lingering user manager) can attach to the
//! harness and run its granted commands from inside the scope, so the install
//! refuses, and refuses a value it cannot read. `--raise-ptrace-scope` at 0
//! writes the sysctl drop-in alone and leaves the agent path off until the
//! value is live (OD9 f-b). It never lowers a value and never writes without
//! the flag.

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

/// What `--agent-path` needs from the harness registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Registry {
    /// Every service-way harness's account, the only accounts `enrol` adds to
    /// the agent group, or why the registry could not be read. A user a
    /// session harness names is not one: a session harness keeps the
    /// password path, and that user in the group would only be a human with
    /// a password in reach of the passwordless helper.
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
                .filter(|entry| entry.way == HarnessWay::Service)
                .filter_map(|entry| entry.account.clone())
                .collect()),
        },
    };
    Registry { accounts }
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

/// What `--agent-path` runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentPlan {
    /// The plan.
    pub(crate) plan: InstallPlan,
    /// The plan writes only the ptrace drop-in: the live value is 0, and the
    /// agent path stays off until it is 1 or more.
    pub(crate) waits_for_scope: bool,
}

/// Builds the opt-in plan, or says why not and returns the exit status.
///
/// `raise` is `--raise-ptrace-scope`. The drop-in is planned only when the
/// live value is 0, and then alone: a drop-in changes nothing until it is
/// applied, and the agent path is turned on only on the live value. At 1 or
/// more there is nothing to raise, and writing 1 over a higher value set at
/// run time would lower it on `sysctl --system`.
pub(crate) fn plan(
    host: &dyn HostView,
    backend: &Backend,
    registry: &Registry,
    raise: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<AgentPlan, ExitCode> {
    if backend.kind == BackendKind::Doas {
        let _ = writeln!(err, "xudo: refusing --agent-path: {AGENT_PATH_SUDO_ONLY}");
        return Err(ExitCode::Unusable);
    }
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
    // The listing checks ask the backend about nobody and the member; it
    // answers an account it does not know on standard error, which is no
    // answer, and the install would be undone after its write.
    for name in [Some("nobody"), member.as_deref()].into_iter().flatten() {
        match xudo_backend::agent_path::account_exists(host, name) {
            Ok(true) => {}
            Ok(false) => refusals.push(format!(
                "the checks after the write ask the backend about {name}, and /etc/passwd \
                 holds no such account"
            )),
            Err(why) => refusals.push(format!(
                "the accounts the checks after the write ask about cannot be known: {why}"
            )),
        }
    }
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
    let scope = match ptrace_gate(host, backend, raise, out, err)? {
        Scope::Live(scope) => scope,
        Scope::Waits(plan) => return Ok(plan),
    };
    if raise {
        let _ = writeln!(
            out,
            "kernel.yama.ptrace_scope is already {scope}: --raise-ptrace-scope writes nothing"
        );
    }
    agent_plan_for(backend, member.as_deref())
        .map(|plan| AgentPlan {
            plan,
            waits_for_scope: false,
        })
        .map_err(|reason| {
            let _ = writeln!(err, "xudo: no usable backend: {reason}");
            ExitCode::Unusable
        })
}

/// What the live `kernel.yama.ptrace_scope` lets `--agent-path` do.
enum Scope {
    /// 1 or more: the agent path may be planned.
    Live(u8),
    /// 0, with `--raise-ptrace-scope`: the drop-in alone.
    Waits(AgentPlan),
}

/// Refuses the agent path at a live `kernel.yama.ptrace_scope` of 0, or one
/// that cannot be read, and plans the drop-in alone at 0 with the flag.
fn ptrace_gate(
    host: &dyn HostView,
    backend: &Backend,
    raise: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Scope, ExitCode> {
    // At 0 any process of an enrolled agent's account outside its unit can
    // attach to the harness and act from inside its scope. The live value
    // decides, never a drop-in's promise, and one that cannot be read is 0.
    let scope = match ptrace_scope(host) {
        Ok(scope) => scope,
        Err(why) => {
            let _ = writeln!(
                err,
                "xudo: refusing --agent-path: kernel.yama.ptrace_scope cannot be read ({why}), \
                 so nothing shows that a process of an agent's account outside its unit cannot \
                 attach to the harness. Nothing was written."
            );
            return Err(ExitCode::Unusable);
        }
    };
    if scope == 0 && !raise {
        let _ = writeln!(
            err,
            "xudo: refusing --agent-path: kernel.yama.ptrace_scope is 0. At 0 any process of an \
             enrolled agent's account outside its unit (an SSH key login, a cron or at job, a \
             lingering user manager) can attach to the harness and run its granted commands \
             with no password. Raise it first: `sudo xudo install --agent-path \
             --raise-ptrace-scope` writes {PTRACE_DROP_IN_PATH}; then run \
             `sudo sysctl --system` and this install again. Nothing was written."
        );
        return Err(ExitCode::Unusable);
    }
    if scope == 0 {
        let _ = writeln!(out, "--- /dev/null\n+++ {PTRACE_DROP_IN_PATH}");
        for line in PTRACE_DROP_IN.lines() {
            let _ = writeln!(out, "+{line}");
        }
        let _ = writeln!(
            out,
            "xudo writes this file and does not apply it: it takes effect with \
             `sudo sysctl --system` or at boot, and only if no file read after it sets the \
             value too. The agent path stays off until the live value is 1 or more."
        );
        for setting in later_ptrace_settings(host) {
            let _ = writeln!(
                err,
                "xudo: warning: {setting}, so the drop-in does not decide the value and the \
                 scope may stay at 0"
            );
        }
        return Ok(Scope::Waits(AgentPlan {
            plan: InstallPlan::ptrace_drop_in(backend.kind),
            waits_for_scope: true,
        }));
    }
    Ok(Scope::Live(scope))
}

/// The opt-in plan, with its failure as text. Detection refuses a backend
/// that cannot be given a snippet first, so only a test reaches the error.
fn agent_plan_for(backend: &Backend, member: Option<&str>) -> Result<InstallPlan, String> {
    InstallPlan::with_agent_path(backend, member).map_err(|source| source.to_string())
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
        .file(
            "/etc/passwd",
            0,
            0,
            0o644,
            b"root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/bin/false\n",
        )
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
        raise: bool,
    ) -> (Result<InstallPlan, ExitCode>, String, String) {
        let registry = Registry {
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
        // A plan that waits for the live value writes the drop-in alone.
        if let Ok(planned) = &result {
            assert_eq!(planned.waits_for_scope, writes_drop_in(&planned.plan));
        }
        (
            result.map(|planned| planned.plan),
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// Every file the plan renames into place.
    fn installed(plan: &InstallPlan) -> Vec<&str> {
        plan.steps
            .iter()
            .filter_map(|step| match step {
                PlanStep::Install { to, .. } => Some(to.as_str()),
                _ => None,
            })
            .collect()
    }

    fn writes_drop_in(plan: &InstallPlan) -> bool {
        plan.steps
            .iter()
            .any(|step| matches!(step, PlanStep::Install { to, .. } if to == PTRACE_DROP_IN_PATH))
    }

    #[test]
    fn the_agent_path_refuses_doas() {
        let (result, out, err) = planned(&host(Some(b"1\n")), BackendKind::Doas, false);
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
        let (result, _, err) = planned(&host, BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(err.contains("/etc/sudoers.d/00-ops line 1"), "{err}");
        assert!(err.contains("Nothing was written"), "{err}");
    }

    #[test]
    fn agent_path_refuses_at_ptrace_scope_zero() {
        // Attack: at 0 an SSH key login, a cron job or a lingering user
        // manager of the agent's account attaches to the harness and runs its
        // granted commands from inside the scope. Without the flag nothing is
        // planned, and the operator is told how to raise it.
        let (result, out, err) = planned(&host(Some(b"0\n")), BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert_eq!(out, "");
        assert!(err.contains("kernel.yama.ptrace_scope is 0"), "{err}");
        assert!(err.contains("an SSH key login, a cron or at job"), "{err}");
        assert!(err.contains("--raise-ptrace-scope"), "{err}");
        assert!(err.contains("`sudo sysctl --system`"), "{err}");
        assert!(err.contains("Nothing was written"), "{err}");
    }

    #[test]
    fn raise_flag_writes_dropin_but_install_waits_for_live_value() {
        // A drop-in is a promise about the next boot, not the live value: at 0
        // the flag plans the drop-in alone, and the agent path stays off.
        let (result, out, _) = planned(&host(Some(b"0\n")), BackendKind::Sudo, true);
        let plan = result.unwrap();
        assert!(writes_drop_in(&plan));
        assert_eq!(installed(&plan), [PTRACE_DROP_IN_PATH]);
        assert!(
            out.contains("+++ /etc/sysctl.d/05-xudo-ptrace-scope.conf"),
            "{out}"
        );
        assert!(out.contains("+kernel.yama.ptrace_scope = 1"), "{out}");
        assert!(out.contains("The agent path stays off"), "{out}");
    }

    #[test]
    fn the_drop_in_never_lowers_a_higher_value() {
        // 1, 2 or 3 is already at least what the drop-in sets: nothing written,
        // and the agent path is planned.
        for now in [&b"1\n"[..], b"2\n", b"3"] {
            let (result, out, _) = planned(&host(Some(now)), BackendKind::SudoRs, true);
            let plan = result.unwrap();
            assert!(!writes_drop_in(&plan));
            assert_eq!(installed(&plan), [SUDOERS_PATH]);
            assert!(out.contains("already"), "{out}");
        }
    }

    #[test]
    fn an_unreadable_ptrace_scope_refuses_the_agent_path_and_writes_nothing() {
        // Fail closed: a value nobody can read may be 0.
        for host in [
            host(None),
            host(Some(b"zero\n")),
            host(Some(&[0xff])),
            host(None).unreadable_file(PTRACE_SCOPE, 0, 0, 0o600),
        ] {
            for raise in [false, true] {
                let (result, _, err) = planned(&host, BackendKind::Sudo, raise);
                assert_eq!(result.unwrap_err(), ExitCode::Unusable);
                assert!(err.contains("cannot be read"), "{err}");
                assert!(err.contains("Nothing was written"), "{err}");
            }
        }
    }

    #[test]
    fn a_backend_with_no_honest_snippet_gets_no_agent_plan() {
        let crippled = Backend {
            capabilities: CapabilityMatrix::empty(),
            ..backend(BackendKind::Sudo)
        };
        assert!(
            agent_plan_for(&crippled, None)
                .unwrap_err()
                .contains("cannot generate")
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &host(Some(b"1")),
            &crippled,
            &Registry {
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
    fn only_a_service_way_account_belongs_in_the_agent_group() {
        let service = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
        let session = "label = \"dev\"\nway = \"session\"\nusers = [\"carol\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n";
        let both = LoadedRules::from_dir(&registry_dir(
            "session",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        assert_eq!(
            registry(both.as_ref()).accounts,
            Ok(vec!["agent".to_owned()])
        );
        let faulty = LoadedRules::from_dir(&registry_dir("fault", &[("x.toml", "wat = 1\n")]));
        assert!(registry(faulty.as_ref()).accounts.is_err());
        let missing = LoadedRules::from_dir(Path::new("/xudo-test-no-such-rules"));
        assert!(registry(missing.as_ref()).accounts.is_err());
    }

    #[test]
    fn a_helper_anyone_but_root_could_swap_stops_the_install() {
        let gate = xudo_backend::snippet::GATE_NOPASS;
        for host in [
            host(Some(b"1\n")).file(gate, 0, 1000, 0o775, b"gate"),
            host(Some(b"1\n")).dir("/usr/libexec/xudo", 1000, 1000, 0o755),
            host(Some(b"1\n")).hard_linked(gate),
        ] {
            let (result, out, err) = planned(&host, BackendKind::Sudo, false);
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
                b"agent:x:990:990::/:/bin/sh\nlurker:x:991:997::/:/bin/sh\n\
                  nobody:x:65534:65534::/:/bin/false\n",
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
            let (result, _, err) = planned(&host, BackendKind::Sudo, false);
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
        let (result, _, err) = planned(&host, BackendKind::Sudo, false);
        assert_eq!(listed_users(&result.unwrap()), ["nobody", "agent"], "{err}");
        // A registered name that could be read as an option is never passed
        // to the backend: nobody stands in.
        let odd = with_members(b"xudo-agent:x:996:-x\n");
        let registry = Registry {
            accounts: Ok(vec!["-x".to_owned()]),
        };
        let (result, _, _) = planned_with(&odd, BackendKind::Sudo, &registry, false);
        assert_eq!(listed_users(&result.unwrap()), ["nobody"]);
        assert!(is_plain_name("svc-agent.1_b"));
        assert!(!is_plain_name("a b"));
    }

    #[test]
    fn members_nobody_can_vouch_for_stop_the_install() {
        // The registry could not be read: no member can be shown to belong.
        let members = with_members(b"xudo-agent:x:996:agent\n");
        let unread = Registry {
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
        let (result, _, err) = planned(&unreadable, BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("the members of xudo-agent cannot be known"),
            "{err}"
        );
    }

    #[test]
    fn a_session_user_added_to_the_agent_group_by_hand_stops_the_install() {
        // carol may start a session of a session harness. In xudo-agent she
        // would reach the passwordless helper with no password; enrol never
        // puts her there, so the install refuses and names her.
        let service = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
        let session = "label = \"dev\"\nway = \"session\"\nusers = [\"carol\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n";
        let rules = LoadedRules::from_dir(&registry_dir(
            "session-member",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        let registry = registry(rules.as_ref());
        let host = with_members(b"xudo-agent:x:996:agent,carol\n");
        let (result, _, err) = planned_with(&host, BackendKind::Sudo, &registry, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("refusing --agent-path: carol is in xudo-agent and no harness"),
            "{err}"
        );
        assert!(!err.contains("agent is in xudo-agent"), "{err}");
    }

    #[test]
    fn a_listing_about_an_account_passwd_does_not_hold_stops_before_the_write() {
        // sudo says `unknown user` on standard error, which is no answer; so
        // nobody, and the member asked about, must exist before anything is
        // written.
        let no_nobody =
            host(Some(b"1\n")).file("/etc/passwd", 0, 0, 0o644, b"root:x:0:0::/root:/bin/sh\n");
        let (result, _, err) = planned(&no_nobody, BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("ask the backend about nobody, and /etc/passwd holds no such account"),
            "{err}"
        );
        // agent is in the group and registered, and has no passwd line.
        let ghost = host(Some(b"1\n")).file("/etc/group", 0, 0, 0o644, b"xudo-agent:x:996:agent\n");
        let (result, _, err) = planned(&ghost, BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(err.contains("about agent, and /etc/passwd holds"), "{err}");
        // /etc/passwd unreadable: nothing can be asked about.
        let unread = host(Some(b"1\n")).unreadable_file("/etc/passwd", 0, 0, 0o600);
        let (result, _, err) = planned(&unread, BackendKind::Sudo, false);
        assert_eq!(result.unwrap_err(), ExitCode::Unusable);
        assert!(
            err.contains("the accounts the checks after the write ask about cannot be known"),
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
        let (result, out, err) = planned(&host, BackendKind::Sudo, true);
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
    fn only_a_service_harness_account_is_a_registered_member() {
        let service = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
        let session = "label = \"dev\"\nway = \"session\"\nusers = [\"carol\", \"dave\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n";
        let both = LoadedRules::from_dir(&registry_dir(
            "accounts",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        // Only the service account: carol and dave may start a session, and
        // a session harness keeps the password path.
        assert_eq!(registry(both.as_ref()).accounts.unwrap(), ["agent"]);
        let faulty =
            LoadedRules::from_dir(&registry_dir("accounts-fault", &[("x.toml", "wat = 1\n")]));
        assert!(registry(faulty.as_ref()).accounts.is_err());
        let missing = LoadedRules::from_dir(Path::new("/xudo-test-no-such-rules"));
        assert!(registry(missing.as_ref()).accounts.is_err());
    }
}
