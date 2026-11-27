//! `xudo install --agent-path`: the checks the front-end makes before it
//! hands the executor the opt-in plan.
//!
//! The plan itself is `xudo_backend::InstallPlan::with_agent_path`, and the
//! executor runs its refusal probe and edit checks. What is decided here reads
//! the machine: doas is refused, any other sudo or doas line that names the
//! agent group or the passwordless helper stops the install, and the host's
//! `kernel.yama.ptrace_scope` decides what `--raise-ptrace-scope` writes
//! (OD9 f-b). It never lowers a value and never writes without the flag.

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
    session: &SessionHarness,
    raise: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<InstallPlan, ExitCode> {
    if backend.kind == BackendKind::Doas {
        let _ = writeln!(err, "xudo: refusing --agent-path: {AGENT_PATH_SUDO_ONLY}");
        return Err(ExitCode::Unusable);
    }
    let conflicts = xudo_backend::agent_path::conflicts(host);
    if !conflicts.is_empty() {
        for conflict in &conflicts {
            let _ = writeln!(err, "xudo: refusing --agent-path: {conflict}");
        }
        let _ = writeln!(
            err,
            "xudo: xudo's line must be the only one for the agent group and the passwordless \
             helper; change or remove those, then run the install again. Nothing was written."
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
            "The value takes effect at the next boot, or now with `sudo sysctl --system`."
        );
    }
    agent_plan_for(backend, raise).map_err(|reason| {
        let _ = writeln!(err, "xudo: no usable backend: {reason}");
        ExitCode::Unusable
    })
}

/// The opt-in plan, with its failure as text. Detection refuses a backend
/// that cannot be given a snippet first, so only a test reaches the error.
fn agent_plan_for(backend: &Backend, raise: bool) -> Result<InstallPlan, String> {
    InstallPlan::with_agent_path(backend, raise).map_err(|source| source.to_string())
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

    /// `plan`, with what it printed.
    fn planned(
        host: &MemoryHost,
        kind: BackendKind,
        session: &SessionHarness,
        raise: bool,
    ) -> (Result<InstallPlan, ExitCode>, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(host, &backend(kind), session, raise, &mut out, &mut err);
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
            agent_plan_for(&crippled, false)
                .unwrap_err()
                .contains("cannot generate")
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &host(Some(b"1")),
            &crippled,
            &SessionHarness::None,
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
    fn registry(name: &str, entries: &[(&str, &str)]) -> PathBuf {
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
        let only_service = LoadedRules::from_dir(&registry("service", &[("codex.toml", service)]));
        assert_eq!(session_harness(only_service.as_ref()), SessionHarness::None);
        let both = LoadedRules::from_dir(&registry(
            "session",
            &[("codex.toml", service), ("dev.toml", session)],
        ));
        assert_eq!(session_harness(both.as_ref()), SessionHarness::Registered);
        let faulty = LoadedRules::from_dir(&registry("fault", &[("x.toml", "wat = 1\n")]));
        assert!(format!("{:?}", session_harness(faulty.as_ref())).starts_with("Unknown("));
        let missing = LoadedRules::from_dir(Path::new("/xudo-test-no-such-rules"));
        assert!(format!("{:?}", session_harness(missing.as_ref())).starts_with("Unknown("));
    }
}
