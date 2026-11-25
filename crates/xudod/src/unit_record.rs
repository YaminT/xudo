//! The record an enrolled service's unit writes about itself: the logic of
//! `xudo-session record <label>` and `xudo-session void <label>`.
//!
//! A service harness is not started through a scope xudo created; systemd
//! starts `xudo-agent@<label>.service` under `xudo.slice`. `ExecStartPre=+`
//! runs `record` as root, and the record it writes, `svc-<label>` under
//! `/run/xudo/sessions`, is what lets the kernel-attested cgroup of a caller
//! name a harness (invariant 1: the cgroup and a root-written record, never a
//! program name or an environment). `ExecStopPost=+` runs `void`.
//!
//! The helper is the only thing that writes such a record, so it refuses
//! everything that is not exactly the unit it describes. It writes a record
//! and nothing else: it grants no run, and no caller skips a password because
//! of it (that gate is a later step).
//!
//! `record` replaces an old record by removing it and then publishing the new
//! one; between the two there is no record, so the unit is unattested, which
//! fails closed. `void` requires parent pid 1, so a caller that is not the
//! service manager cannot void: H2c's `agent remove` must stop the unit and
//! let its `ExecStopPost` void the record.
//!
//! | Refused unless | Because |
//! |---|---|
//! | uid 0 | only root may write authority |
//! | parent pid 1 | only the service manager starts a unit's pre-start |
//! | user, pid, cgroup and mount namespaces are pid 1's | a root in a namespace of its own is not the host's root |
//! | own cgroup is exactly `/xudo.slice/xudo-agent@<label>.service` | a record for another unit is a record for the wrong harness |
//! | that directory is root-owned, not group/other writable, populated | a directory an administrator did not make is no unit of ours |
//! | the registry has `<label>` with `way = service` | no registry entry, no harness |
//! | `/etc/xudo/agents/<label>.env` is absent, or a root-owned regular file, mode `0600`-like (no group/other bit), not a link, in a root-owned directory nobody else can write | systemd applies that file to this root helper's own environment without checking it |
//! | its account resolves in `/etc/passwd` to a non-zero uid | the record names the uid the kernel will report |

use std::ffi::OsString;
use std::path::Path;

use thiserror::Error;
use xudo_policy::{HarnessWay, passwd_uid};
use xudo_sys::{
    CgroupCalls, Clock, EnvFileProbe, EnvFiles, HostCgroup, HostClock, HostEnvFiles, HostOwn,
    HostSyscalls, OwnFacts, ProcRef, ProcSource, Spool, SpoolDir, SpoolError, SysError, Syscalls,
    VerifiedProc, process_cgroup, service_record_name,
};

use xudo_sys::trust::{Kind, PathFacts};

use crate::policy::{HostPolicy, PolicySource};

/// Where committed records live.
pub const SESSIONS_DIR: &str = "/run/xudo/sessions";

/// The parent every unit's pre-start and post-stop command has.
const SERVICE_MANAGER: u32 = 1;

/// Why a record was not written or removed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UnitRecordError {
    /// The command line is not `record <label>` or `void <label>`.
    #[error("usage: xudo-session record <label> | void <label>")]
    Usage,
    /// Not uid 0.
    #[error("refused: not run as root")]
    NotRoot,
    /// Not started by the service manager.
    #[error("refused: not started by pid 1")]
    NotFromInit,
    /// The helper is in a namespace that is not pid 1's, or `/proc` is not
    /// the host's.
    #[error("refused: not in the host's namespaces")]
    ForeignNamespace,
    /// The helper is not inside the unit it was asked to describe.
    #[error("refused: the process is in {found}, not in {expected}")]
    NotInUnit {
        /// The unit's cgroup path.
        expected: String,
        /// The process's own cgroup path.
        found: String,
    },
    /// The unit directory is not one root made and protects.
    #[error("refused: the unit's cgroup directory is not root-owned, protected and populated")]
    UnitUntrusted,
    /// The registry has no service entry for the label.
    #[error("refused: {label} is not a service harness in the registry")]
    NotAService {
        /// The label asked for.
        label: String,
    },
    /// The unit's environment file is one root did not make and protect.
    #[error(
        "refused: the environment file of {label} is not a root-owned private regular file in a protected directory"
    )]
    EnvFileUntrusted {
        /// The label asked for.
        label: String,
    },
    /// The registered account is missing from `/etc/passwd` or is root.
    #[error("refused: the account of {label} is not a non-root account in /etc/passwd")]
    NoAccount {
        /// The label asked for.
        label: String,
    },
    /// The record would not validate as the gate parses it.
    #[error("refused: the record would not validate")]
    Invalid,
    /// A host read or write failed.
    #[error("refused: {0}")]
    Unavailable(String),
}

impl UnitRecordError {
    /// The exit status: 2 for a bad command line, 1 for every refusal.
    #[must_use]
    pub fn status(&self) -> u8 {
        match self {
            Self::Usage => 2,
            _ => 1,
        }
    }
}

fn unavailable(what: &str, error: &impl std::fmt::Display) -> UnitRecordError {
    UnitRecordError::Unavailable(format!("{what}: {error}"))
}

/// What the helper asks of the host.
pub struct Env<'a> {
    /// The helper's own uid and `/proc/self/stat`.
    pub own: &'a dyn OwnFacts,
    /// The pinned cgroup2 tree, or why there is none.
    pub cgroups: Result<&'a dyn CgroupCalls, &'a SysError>,
    /// The session-record directory, or why it did not open.
    pub sessions: Result<&'a dyn Spool, &'a SpoolError>,
    /// The pinned `/proc`, or why there is none.
    pub proc: Result<&'a dyn ProcSource, &'a SysError>,
    /// The unit's optional environment file.
    pub envfiles: &'a dyn EnvFiles,
    /// The boot id.
    pub syscalls: &'a dyn Syscalls,
    /// `CLOCK_BOOTTIME`.
    pub clock: &'a dyn Clock,
    /// Root's rules and registry, and `/etc/passwd`.
    pub policy: &'a dyn PolicySource,
}

/// What the entry point prints and exits with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// The process exit status.
    pub status: u8,
    /// A line for standard error; empty on success.
    pub message: String,
}

/// Runs `argv` (program name first) against this host.
#[must_use]
pub fn run(argv: &[OsString]) -> Exit {
    let cgroups = HostCgroup::open();
    let sessions = SpoolDir::open(Path::new(SESSIONS_DIR));
    let policy = HostPolicy::system();
    let envfiles = HostEnvFiles::system();
    let proc = VerifiedProc::open();
    execute(
        argv,
        &Env {
            own: &HostOwn,
            cgroups: cgroups_seam(&cgroups),
            sessions: xudo_sys::as_seam(&sessions),
            proc: proc_seam(&proc),
            envfiles: &envfiles,
            syscalls: &HostSyscalls,
            clock: &HostClock,
            policy: &policy,
        },
    )
}

/// The opened `/proc` as the trait object [`Env`] takes.
fn proc_seam<T: ProcSource>(opened: &Result<T, SysError>) -> Result<&dyn ProcSource, &SysError> {
    match opened {
        Ok(proc) => Ok(proc),
        Err(error) => Err(error),
    }
}

/// The opened cgroup tree as the trait object [`Env`] takes. Generic so a test
/// reaches both arms on a host where the real tree never opens.
fn cgroups_seam<T: CgroupCalls>(
    opened: &Result<T, SysError>,
) -> Result<&dyn CgroupCalls, &SysError> {
    match opened {
        Ok(calls) => Ok(calls),
        Err(error) => Err(error),
    }
}

/// Runs `argv` (program name first) against `env`.
#[must_use]
pub fn execute(argv: &[OsString], env: &Env<'_>) -> Exit {
    match dispatch(argv, env) {
        Ok(()) => Exit {
            status: 0,
            message: String::new(),
        },
        Err(error) => Exit {
            status: error.status(),
            message: format!("xudo-session: {error}"),
        },
    }
}

fn dispatch(argv: &[OsString], env: &Env<'_>) -> Result<(), UnitRecordError> {
    let mut words = argv.iter().skip(1).map(|word| word.to_str());
    let (Some(Some(verb)), Some(Some(label)), None) = (words.next(), words.next(), words.next())
    else {
        return Err(UnitRecordError::Usage);
    };
    match verb {
        "record" => record(env, label),
        "void" => void(env, label),
        _ => Err(UnitRecordError::Usage),
    }
}

/// The two checks both commands make: root, started by the service manager.
/// Returns the helper's own pid and start time.
fn started_by_the_service_manager(env: &Env<'_>) -> Result<(u32, u64), UnitRecordError> {
    if env.own.uid() != 0 {
        return Err(UnitRecordError::NotRoot);
    }
    let stat = env.own.stat().map_err(|e| unavailable("own stat", &e))?;
    if stat.ppid != SERVICE_MANAGER {
        return Err(UnitRecordError::NotFromInit);
    }
    // The same check the gate makes of a caller: a root in a user, pid,
    // cgroup or mount namespace of its own is not the host's root.
    let proc = env.proc.map_err(|e| unavailable("/proc", &e))?;
    let process = ProcRef {
        pid: stat.pid,
        starttime: stat.starttime,
        comm: Vec::new(),
    };
    if !xudo_gate::live::read(proc, &process).namespaces_match_init {
        return Err(UnitRecordError::ForeignNamespace);
    }
    Ok((stat.pid, stat.starttime))
}

/// Writes `svc-<label>` for the unit the caller is in, replacing any old one
/// (remove, then publish; see the module note).
///
/// # Errors
///
/// Returns the first requirement of the module table that does not hold.
pub fn record(env: &Env<'_>, label: &str) -> Result<(), UnitRecordError> {
    let name = service_record_name(label).ok_or(UnitRecordError::Usage)?;
    let (pid, starttime) = started_by_the_service_manager(env)?;
    let unit = format!("xudo-agent@{label}.service");
    let cgroups = env
        .cgroups
        .map_err(|e| unavailable("cgroup2 is not available", &e))?;
    cgroups
        .require_cgroup2()
        .map_err(|e| unavailable("cgroup2", &e))?;
    let (path, id) = process_cgroup(cgroups, pid).map_err(|e| unavailable("own cgroup", &e))?;
    let expected = format!("/xudo.slice/{unit}");
    if path != expected {
        return Err(UnitRecordError::NotInUnit {
            expected,
            found: path,
        });
    }
    let facts = cgroups
        .scope_facts(&unit, id, false)
        .map_err(|e| unavailable("unit cgroup", &e))?;
    // The same ownership and liveness `scope_status` demands of any scope.
    let trusted = facts.as_ref().is_some_and(|facts| {
        facts.cgroup2
            && facts.inode == id
            && facts.owner == 0
            && facts.mode & 0o022 == 0
            && facts.procs_owner == 0
            && facts.procs_mode & 0o022 == 0
            && facts.populated
    });
    if !trusted {
        return Err(UnitRecordError::UnitUntrusted);
    }

    env_file_is_trusted(env, label)?;

    let loaded = env.policy.load().map_err(|e| unavailable("policy", &e))?;
    let registry = &loaded.rules.harnesses;
    let entry = registry
        .get(label)
        .filter(|entry| entry.way == HarnessWay::Service)
        .ok_or_else(|| UnitRecordError::NotAService {
            label: label.to_owned(),
        })?;
    let uid = entry
        .account
        .as_deref()
        .and_then(|account| passwd_uid(&loaded.passwd, account))
        .filter(|uid| *uid != 0)
        .ok_or_else(|| UnitRecordError::NoAccount {
            label: label.to_owned(),
        })?;

    let boot_id = env
        .syscalls
        .boot_id()
        .map_err(|e| unavailable("boot id", &e))?;
    let now = env.clock.boottime_millis();
    let bytes = serde_json::json!({
        "uid": uid,
        "label": label,
        "way": "service",
        "registry_entry_hash": entry.hash_hex(),
        "boot_id": boot_id,
        "created_at_boottime_ms": now,
        "deadline": xudo_gate::NO_DEADLINE,
        "pid": pid,
        "starttime": starttime,
        "cgroup_id": id,
    })
    .to_string()
    .into_bytes();
    // What the gate will parse, against the registry it will read: a record
    // that would not attest is not written.
    xudo_gate::record_identity_registered(
        &bytes,
        &name,
        uid,
        &boot_id,
        now,
        registry,
        &loaded.passwd,
    )
    .ok_or(UnitRecordError::Invalid)?;

    let sessions = env
        .sessions
        .map_err(|e| unavailable("session records", &e))?;
    // A crash between creating the temporary file and renaming it leaves it
    // behind, and `publish` creates it exclusively: clear it first.
    for stale in [format!("{}{name}", xudo_sys::TEMP_PREFIX), name.clone()] {
        sessions
            .remove(stale.as_bytes())
            .map_err(|e| unavailable("replace the old record", &e))?;
    }
    sessions
        .publish(&name, &bytes)
        .map_err(|e| unavailable("write the record", &e))
}

/// systemd feeds `<label>.env` to the root helper's own environment unchecked:
/// refuse unless it is absent or [`env_file_is_private`].
fn env_file_is_trusted(env: &Env<'_>, label: &str) -> Result<(), UnitRecordError> {
    match env
        .envfiles
        .probe(label)
        .map_err(|e| unavailable("environment file", &e))?
    {
        EnvFileProbe::Present { file, dir } if !env_file_is_private(&file, &dir) => {
            Err(UnitRecordError::EnvFileUntrusted {
                label: label.to_owned(),
            })
        }
        EnvFileProbe::Present { .. } | EnvFileProbe::Absent => Ok(()),
    }
}

/// A regular file (not a link) of root's with no group or other permission,
/// in a directory that is root's and that no one else can write.
fn env_file_is_private(file: &PathFacts, dir: &PathFacts) -> bool {
    file.kind == Kind::File
        && file.uid == 0
        && file.mode.trailing_zeros() >= 6
        && dir.kind == Kind::Directory
        && dir.uid == 0
        && dir.mode & 0o022 == 0
}

/// Removes `svc-<label>`; a record that is already gone is fine.
///
/// # Errors
///
/// Returns an error unless root, started by pid 1, with the directory open.
pub fn void(env: &Env<'_>, label: &str) -> Result<(), UnitRecordError> {
    let name = service_record_name(label).ok_or(UnitRecordError::Usage)?;
    started_by_the_service_manager(env)?;
    let sessions = env
        .sessions
        .map_err(|e| unavailable("session records", &e))?;
    sessions
        .remove(name.as_bytes())
        .map(drop)
        .map_err(|e| unavailable("remove the record", &e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;
    use std::os::fd::BorrowedFd;

    use xudo_gate::policy::{LoadedPolicy, PolicyError};
    use xudo_policy::{HarnessRegistry, RuleFile, load_rule_files};
    use xudo_sys::{
        EnvFileProbe, FakeEnvFiles, FakeOwn, FakeSpool, FakeSyscalls, FixedClock, MapSource,
        ScopeFacts, SpoolCall, unit_dir_name,
    };

    use super::*;

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";
    const UNIT_PATH: &str = "/xudo.slice/xudo-agent@codex.service";
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nagent:x:1001:1001::/home/agent:/bin/sh\n";
    const CODEX: &str = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n";
    const CLAUDE: &str = "label = \"claude\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n";
    const SESSION: &str = "label = \"codex\"\nway = \"session\"\nusers = [\"alice\"]\nreviewers = [\"bob\"]\nmax-sessions = 4\n";

    const RULES: &str = r#"
[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

    fn trusted_facts(inode: u64) -> ScopeFacts {
        ScopeFacts {
            cgroup2: true,
            inode,
            owner: 0,
            mode: 0o40_755,
            procs_owner: 0,
            procs_mode: 0o100_644,
            populated: true,
            record: None,
            record_owner: 0,
            record_mode: 0,
            record_nlink: 0,
            processes: Vec::new(),
        }
    }

    /// A cgroup tree the helper's own process is placed in.
    struct Cgroups {
        path: String,
        inode: u64,
        facts: RefCell<Result<Option<ScopeFacts>, SysError>>,
        cgroup2: Result<(), SysError>,
        proc: Result<Vec<u8>, SysError>,
        asked_unit: RefCell<Vec<String>>,
    }

    impl Cgroups {
        fn in_unit(path: &str) -> Self {
            Self {
                path: path.to_owned(),
                inode: 77,
                facts: RefCell::new(Ok(Some(trusted_facts(77)))),
                cgroup2: Ok(()),
                proc: Ok(format!("0::{path}\n").into_bytes()),
                asked_unit: RefCell::new(Vec::new()),
            }
        }
    }

    impl CgroupCalls for Cgroups {
        fn require_cgroup2(&self) -> Result<(), SysError> {
            self.cgroup2.clone()
        }
        fn pidfd_cgroup_id(&self, _: BorrowedFd<'_>) -> Result<u64, SysError> {
            Err(SysError::unsupported("not used by the helper"))
        }
        fn proc_cgroup(&self, _: u32) -> Result<Vec<u8>, SysError> {
            self.proc.clone()
        }
        fn cgroup_inode(&self, path: &str) -> Result<u64, SysError> {
            assert_eq!(path, self.path);
            Ok(self.inode)
        }
        fn peer_alive(&self, _: BorrowedFd<'_>) -> Result<bool, SysError> {
            Ok(true)
        }
        fn scope_facts(
            &self,
            name: &str,
            id: u64,
            with_processes: bool,
        ) -> Result<Option<ScopeFacts>, SysError> {
            assert_eq!(id, self.inode);
            assert!(!with_processes);
            self.asked_unit.borrow_mut().push(name.to_owned());
            self.facts.borrow().clone()
        }
        fn scope_names(&self) -> Result<Vec<String>, SysError> {
            Ok(Vec::new())
        }
    }

    struct Policy {
        files: Vec<&'static str>,
        passwd: &'static str,
        fail: bool,
    }

    impl PolicySource for Policy {
        fn load(&self) -> Result<LoadedPolicy, PolicyError> {
            if self.fail {
                return Err(PolicyError::Rules(xudo_sys::TrustedRulesError::Trust(
                    xudo_sys::TrustError::NotFound {
                        at: "/etc/xudo/rules.d".to_owned(),
                    },
                )));
            }
            let named = self.files.iter().map(|text| {
                let label = text.split('"').nth(1).unwrap().to_owned();
                (format!("{label}.toml"), (*text).to_owned())
            });
            let mut rules = load_rule_files(vec![RuleFile {
                name: b"10-none.toml".to_vec(),
                bytes: RULES.as_bytes().to_vec(),
            }])
            .unwrap();
            rules.harnesses = HarnessRegistry::from_files(named).unwrap();
            Ok(LoadedPolicy {
                rules,
                settings: xudo_policy::engine::Settings::default(),
                queue_ttl_secs: 0,
                passwd: self.passwd.to_owned(),
                passwd_fault: None,
            })
        }
    }

    /// Everything the helper reads, healthy: pid 1's child, root, in its unit.
    struct World {
        own: FakeOwn,
        cgroups: Cgroups,
        spool: FakeSpool,
        proc: MapSource,
        syscalls: FakeSyscalls,
        clock: FixedClock,
        policy: Policy,
        envfiles: FakeEnvFiles,
    }

    /// The helper's own process, in every namespace pid 1 is in.
    fn host_proc() -> MapSource {
        host_proc_started(71)
    }

    fn host_proc_started(starttime: u64) -> MapSource {
        let mut fields = vec!["S".to_owned(), "1".to_owned()];
        fields.extend((0..17).map(|_| "0".to_owned()));
        fields.push(starttime.to_string());
        let mut proc = MapSource::new()
            .with(
                "500/stat",
                format!("500 (xudo-session) {}", fields.join(" ")),
            )
            .with(
                "500/status",
                "Name:\txudo-session\nUid:\t0\t0\t0\t0\nNSpid:\t500\n",
            )
            .with("500/uid_map", "         0          0 4294967295\n");
        for kind in ["user", "pid", "cgroup", "mnt"] {
            proc = proc
                .with_inode(format!("500/ns/{kind}"), 4_026_531_800)
                .with_inode(format!("1/ns/{kind}"), 4_026_531_800);
        }
        proc
    }

    impl World {
        fn new() -> Self {
            Self {
                own: FakeOwn::new(0, 500, 1, 71),
                cgroups: Cgroups::in_unit(UNIT_PATH),
                spool: FakeSpool::new(),
                proc: host_proc(),
                syscalls: FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
                clock: FixedClock(1_000),
                policy: Policy {
                    files: vec![CODEX],
                    passwd: PASSWD,
                    fail: false,
                },
                envfiles: FakeEnvFiles(Ok(EnvFileProbe::Absent)),
            }
        }

        fn run(&self, words: &[&str]) -> Exit {
            let mut argv = vec![OsString::from("xudo-session")];
            argv.extend(words.iter().map(OsString::from));
            execute(&argv, &self.env())
        }

        fn env(&self) -> Env<'_> {
            Env {
                own: &self.own,
                cgroups: Ok(&self.cgroups),
                sessions: Ok(&self.spool),
                proc: Ok(&self.proc),
                syscalls: &self.syscalls,
                clock: &self.clock,
                policy: &self.policy,
                envfiles: &self.envfiles,
            }
        }

        fn record(&self) -> Result<(), UnitRecordError> {
            record(&self.env(), "codex")
        }

        fn written(&self) -> Option<Vec<u8>> {
            self.spool.files().get(&b"svc-codex"[..]).cloned()
        }
    }

    fn private_file() -> PathFacts {
        PathFacts {
            uid: 0,
            mode: 0o600,
            kind: Kind::File,
        }
    }

    fn present(file: PathFacts, dir: PathFacts) -> FakeEnvFiles {
        FakeEnvFiles(Ok(EnvFileProbe::Present { file, dir }))
    }

    #[test]
    fn a_root_private_env_file_in_a_root_directory_is_accepted() {
        let mut world = World::new();
        world.envfiles = present(private_file(), PathFacts::trusted_directory());
        world.record().unwrap();
        assert!(world.written().is_some());
    }

    #[test]
    fn an_env_file_root_did_not_make_and_protect_is_refused_before_any_record() {
        let bad_files = [
            PathFacts {
                uid: 1001,
                ..private_file()
            },
            PathFacts {
                mode: 0o640,
                ..private_file()
            },
            PathFacts {
                mode: 0o604,
                ..private_file()
            },
            PathFacts {
                kind: Kind::Symlink,
                ..private_file()
            },
            PathFacts {
                kind: Kind::Directory,
                ..private_file()
            },
            PathFacts {
                kind: Kind::Other,
                ..private_file()
            },
        ];
        let dir = PathFacts::trusted_directory();
        let bad_dirs = [
            PathFacts { uid: 1001, ..dir },
            PathFacts { mode: 0o775, ..dir },
            PathFacts { mode: 0o757, ..dir },
            PathFacts {
                kind: Kind::Symlink,
                ..dir
            },
            PathFacts {
                kind: Kind::File,
                ..dir
            },
        ];
        let mut cases: Vec<(PathFacts, PathFacts)> =
            bad_files.iter().map(|file| (*file, dir)).collect();
        cases.extend(bad_dirs.iter().map(|d| (private_file(), *d)));
        for (file, dir) in cases {
            let mut world = World::new();
            world.envfiles = present(file, dir);
            assert_eq!(
                refused(world.record()),
                UnitRecordError::EnvFileUntrusted {
                    label: "codex".to_owned()
                },
                "{file:?} in {dir:?}"
            );
            assert!(world.written().is_none());
            assert!(world.spool.calls().is_empty());
        }
    }

    #[test]
    fn an_env_file_that_cannot_be_inspected_refuses_the_record() {
        let mut world = World::new();
        let error = SysError::read("/etc/xudo/agents", "denied");
        world.envfiles = FakeEnvFiles(Err(error.clone()));
        assert_eq!(
            refused(world.record()),
            UnitRecordError::Unavailable(format!("environment file: {error}"))
        );
        assert!(world.written().is_none());
    }

    fn broken_spool() -> SpoolError {
        SpoolError::Gone {
            name: "svc-codex".to_owned(),
        }
    }

    fn refused(result: Result<(), UnitRecordError>) -> UnitRecordError {
        result.unwrap_err()
    }

    #[test]
    fn a_unit_records_itself_and_the_record_attests_to_the_gate() {
        let world = World::new();
        let exit = world.run(&["record", "codex"]);
        assert_eq!(
            exit,
            Exit {
                status: 0,
                message: String::new()
            }
        );
        let bytes = world.written().unwrap();
        let registry = HarnessRegistry::from_files([("codex.toml", CODEX)]).unwrap();
        let identity = xudo_gate::record_identity_registered(
            &bytes,
            "svc-codex",
            1001,
            BOOT,
            1_000,
            &registry,
            PASSWD,
        )
        .unwrap();
        assert_eq!(identity.cgroup_id, 77);
        assert_eq!(identity.process, (500, 71));
        let parsed =
            xudo_gate::parse_session_record(&bytes, "svc-codex", 1001, BOOT, 1_000).unwrap();
        assert_eq!(parsed.deadline, xudo_gate::NO_DEADLINE);
        assert_eq!(parsed.way, HarnessWay::Service);
        assert_eq!(
            world.cgroups.asked_unit.borrow().as_slice(),
            ["xudo-agent@codex.service"]
        );
        // The name the helper checks is the name the sys layer maps back.
        assert_eq!(
            unit_dir_name(&service_record_name("codex").unwrap()).as_deref(),
            Some("xudo-agent@codex.service")
        );
    }

    #[test]
    fn a_root_in_a_user_namespace_of_its_own_is_refused_by_both_verbs() {
        // `unshare -Ur -pf --mount-proc`: uid 0 and parent 1 inside, but not
        // the host's namespaces.
        for kind in ["user", "pid", "cgroup", "mnt"] {
            let world = World {
                proc: host_proc().with_inode(format!("500/ns/{kind}"), 4_026_539_999),
                ..World::new()
            };
            assert_eq!(
                refused(world.record()),
                UnitRecordError::ForeignNamespace,
                "{kind}"
            );
            assert_eq!(
                refused(void(&world.env(), "codex")),
                UnitRecordError::ForeignNamespace,
                "{kind}"
            );
            assert_eq!(world.written(), None);
            assert!(world.spool.calls().is_empty());
        }
    }

    #[test]
    fn a_host_with_no_proc_refuses_and_a_stale_temporary_record_is_cleared() {
        let world = World::new();
        let no_proc = SysError::unsupported("procfs");
        let env = Env {
            proc: Err(&no_proc),
            ..world.env()
        };
        assert!(refused(record(&env, "codex")).to_string().contains("/proc"));
        assert!(proc_seam(&Err::<MapSource, _>(no_proc)).is_err());
        assert!(proc_seam(&Ok::<_, SysError>(MapSource::new())).is_ok());

        let stale = World {
            spool: FakeSpool::new().with_file(".tmp.svc-codex", b"half".to_vec()),
            ..World::new()
        };
        stale.record().unwrap();
        assert!(stale.written().is_some());
        assert!(!stale.spool.files().contains_key(&b".tmp.svc-codex"[..]));
        let failing = World {
            spool: FakeSpool::new().failing_remove(broken_spool()),
            ..World::new()
        };
        assert!(
            refused(failing.record())
                .to_string()
                .contains("replace the old record")
        );
    }

    #[test]
    fn a_service_restart_gets_a_fresh_record() {
        let world = World::new();
        world.record().unwrap();
        let first = world.written().unwrap();
        let later = World {
            spool: FakeSpool::new().with_file("svc-codex", first.clone()),
            clock: FixedClock(5_000),
            ..World::new()
        };
        later.record().unwrap();
        let second = later.written().unwrap();
        assert_ne!(first, second);
        assert!(
            String::from_utf8(second)
                .unwrap()
                .contains("\"created_at_boottime_ms\":5000")
        );
        // The old record is removed before the new one is published.
        let calls = later.spool.calls();
        let remove = calls
            .iter()
            .position(|c| matches!(c, SpoolCall::Remove(_)))
            .unwrap();
        let publish = calls
            .iter()
            .position(|c| matches!(c, SpoolCall::Publish(_)))
            .unwrap();
        assert!(remove < publish);
    }

    #[test]
    fn the_record_helper_refuses_when_not_started_by_pid_1() {
        for parent in [0, 2, 500, 1000] {
            let world = World {
                own: FakeOwn::new(0, 500, parent, 71),
                ..World::new()
            };
            assert_eq!(refused(world.record()), UnitRecordError::NotFromInit);
            assert_eq!(world.written(), None);
            assert_eq!(
                refused(void(&world.env(), "codex")),
                UnitRecordError::NotFromInit
            );
        }
    }

    #[test]
    fn the_record_helper_refuses_a_caller_that_is_not_root() {
        for uid in [1, 1000, 1001, u32::MAX] {
            let world = World {
                own: FakeOwn::new(uid, 500, 1, 71),
                ..World::new()
            };
            assert_eq!(refused(world.record()), UnitRecordError::NotRoot);
            assert_eq!(
                refused(void(&world.env(), "codex")),
                UnitRecordError::NotRoot
            );
            assert_eq!(world.written(), None);
        }
    }

    #[test]
    fn the_record_helper_refuses_outside_its_own_unit() {
        for path in [
            "/user.slice/user-1000.slice/session-3.scope",
            "/xudo.slice/agent-0123456789abcdef0123456789abcdef.scope",
            "/xudo.slice/xudo-agent@codex.service/child",
            "/system.slice/xudo-agent@codex.service",
            "/xudo.slice/xudo-agent@codex.service/",
            "/xudo.slice/xudo-agent@claude.service",
            "/",
        ] {
            let world = World {
                cgroups: Cgroups::in_unit(path),
                ..World::new()
            };
            let text = refused(world.record()).to_string();
            assert!(
                text.starts_with("refused: the process is in"),
                "{path}: {text}"
            );
            assert_eq!(world.written(), None, "{path}");
        }
    }

    #[test]
    fn a_record_for_one_label_in_another_labels_unit_is_refused() {
        let world = World {
            cgroups: Cgroups::in_unit("/xudo.slice/xudo-agent@claude.service"),
            policy: Policy {
                files: vec![CODEX, CLAUDE],
                passwd: PASSWD,
                fail: false,
            },
            ..World::new()
        };
        assert_eq!(
            refused(world.record()),
            UnitRecordError::NotInUnit {
                expected: UNIT_PATH.to_owned(),
                found: "/xudo.slice/xudo-agent@claude.service".to_owned(),
            }
        );
        // And the unit's own label still records.
        record(&world.env(), "claude").unwrap();
        assert!(world.spool.files().contains_key(&b"svc-claude"[..]));
        assert!(!world.spool.files().contains_key(&b"svc-codex"[..]));
    }

    #[test]
    fn the_record_helper_refuses_a_label_with_no_service_entry() {
        let not_a_service = UnitRecordError::NotAService {
            label: "codex".to_owned(),
        };
        for files in [vec![], vec![CLAUDE], vec![SESSION]] {
            let world = World {
                policy: Policy {
                    files,
                    passwd: PASSWD,
                    fail: false,
                },
                ..World::new()
            };
            assert_eq!(refused(world.record()), not_a_service);
            assert_eq!(world.written(), None);
        }
    }

    #[test]
    fn the_record_helper_refuses_an_account_that_is_missing_or_root() {
        for passwd in [
            "",
            "root:x:0:0:root:/root:/bin/sh\n",
            "agent:x:0:0::/root:/bin/sh\n",
            "agent:x:notanumber:1001::/home/agent:/bin/sh\n",
        ] {
            let world = World {
                policy: Policy {
                    files: vec![CODEX],
                    passwd,
                    fail: false,
                },
                ..World::new()
            };
            assert_eq!(
                refused(world.record()),
                UnitRecordError::NoAccount {
                    label: "codex".to_owned()
                },
                "{passwd:?}"
            );
            assert_eq!(world.written(), None);
        }
    }

    #[test]
    fn a_unit_directory_root_did_not_make_is_not_a_unit() {
        let weaken: [fn(&mut ScopeFacts); 8] = [
            |f| f.cgroup2 = false,
            |f| f.inode = 78,
            |f| f.owner = 1000,
            |f| f.mode = 0o40_775,
            |f| f.procs_owner = 1000,
            |f| f.procs_mode = 0o100_666,
            |f| f.populated = false,
            |f| f.mode = 0o40_757,
        ];
        for change in weaken {
            let mut facts = trusted_facts(77);
            change(&mut facts);
            let world = World::new();
            *world.cgroups.facts.borrow_mut() = Ok(Some(facts));
            assert_eq!(refused(world.record()), UnitRecordError::UnitUntrusted);
            assert_eq!(world.written(), None);
        }
        let world = World::new();
        *world.cgroups.facts.borrow_mut() = Ok(None);
        assert_eq!(refused(world.record()), UnitRecordError::UnitUntrusted);
    }

    #[test]
    fn a_record_that_would_not_validate_is_not_written() {
        // A process start time of 0 is no pin, so the gate would refuse it.
        let world = World {
            own: FakeOwn::new(0, 500, 1, 0),
            proc: host_proc_started(0),
            ..World::new()
        };
        assert_eq!(refused(world.record()), UnitRecordError::Invalid);
        assert_eq!(world.written(), None);
        assert!(world.spool.calls().is_empty());
    }

    #[test]
    fn every_failed_host_read_or_write_refuses_and_writes_nothing() {
        let gone = || SysError::read("x", "gone");
        let cases: Vec<(&str, World)> = vec![
            (
                "own stat",
                World {
                    own: FakeOwn {
                        uid: 0,
                        stat: Err(gone()),
                    },
                    ..World::new()
                },
            ),
            ("cgroup2", {
                let mut world = World::new();
                world.cgroups.cgroup2 = Err(gone());
                world
            }),
            ("own cgroup", {
                let mut world = World::new();
                world.cgroups.proc = Err(gone());
                world
            }),
            ("unit cgroup", {
                let world = World::new();
                *world.cgroups.facts.borrow_mut() = Err(gone());
                world
            }),
            (
                "policy",
                World {
                    policy: Policy {
                        files: vec![],
                        passwd: "",
                        fail: true,
                    },
                    ..World::new()
                },
            ),
            (
                "boot id",
                World {
                    syscalls: FakeSyscalls::new().with_boot_id(Err(gone())),
                    ..World::new()
                },
            ),
            (
                "replace the old record",
                World {
                    spool: FakeSpool::new().failing_remove(broken_spool()),
                    ..World::new()
                },
            ),
            (
                "write the record",
                World {
                    spool: FakeSpool::new().failing_publish(broken_spool()),
                    ..World::new()
                },
            ),
        ];
        for (what, world) in cases {
            let error = refused(world.record());
            let text = error.to_string();
            assert!(
                text.starts_with("refused: ") && text.contains(what),
                "{what}: {text}"
            );
            assert_eq!(world.written(), None, "{what}");
        }
    }

    #[test]
    fn a_host_with_no_cgroup_tree_or_no_session_directory_refuses() {
        let world = World::new();
        let no_tree = SysError::unsupported("cgroup2 attestation");
        let env = Env {
            cgroups: Err(&no_tree),
            ..world.env()
        };
        assert!(
            refused(record(&env, "codex"))
                .to_string()
                .contains("cgroup2 is not available")
        );
        let no_dir = broken_spool();
        let env = Env {
            sessions: Err(&no_dir),
            ..world.env()
        };
        assert!(
            refused(record(&env, "codex"))
                .to_string()
                .contains("session records")
        );
        assert!(
            refused(void(&env, "codex"))
                .to_string()
                .contains("session records")
        );
    }

    #[test]
    fn void_removes_the_record_and_a_missing_one_is_fine() {
        let world = World::new();
        world.record().unwrap();
        assert!(world.written().is_some());
        assert_eq!(world.run(&["void", "codex"]).status, 0);
        assert_eq!(world.written(), None);
        assert_eq!(world.run(&["void", "codex"]).status, 0);
        let failing = World {
            spool: FakeSpool::new().failing_remove(broken_spool()),
            ..World::new()
        };
        let exit = failing.run(&["void", "codex"]);
        assert_eq!(exit.status, 1);
        assert!(exit.message.contains("remove the record"));
    }

    #[test]
    fn a_command_line_that_is_not_record_or_void_and_a_label_is_a_usage_error() {
        let world = World::new();
        for words in [
            &[][..],
            &["record"],
            &["record", "codex", "extra"],
            &["bogus", "codex"],
            &["Record", "codex"],
            &["record", "Codex"],
            &["record", ""],
            &["record", "../codex"],
            &["void", "co dex"],
            &["record", "-codex"],
        ] {
            let exit = world.run(words);
            assert_eq!(exit.status, 2, "{words:?}");
            assert!(exit.message.starts_with("xudo-session: usage"), "{words:?}");
        }
        assert_eq!(execute(&[], &world.env()).status, 2);
        assert!(world.spool.calls().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bytes = OsString::from_vec(vec![b'r', 0xff]);
            let argv = [OsString::from("x"), bytes.clone(), OsString::from("codex")];
            assert_eq!(execute(&argv, &world.env()).status, 2);
            let argv = [OsString::from("x"), OsString::from("record"), bytes];
            assert_eq!(execute(&argv, &world.env()).status, 2);
        }
    }

    #[test]
    fn a_refusal_names_itself_on_standard_error_with_status_one() {
        let world = World {
            own: FakeOwn::new(1000, 500, 1, 71),
            ..World::new()
        };
        let exit = world.run(&["record", "codex"]);
        assert_eq!(exit.status, 1);
        assert_eq!(exit.message, "xudo-session: refused: not run as root");
    }

    #[test]
    fn the_host_helper_run_as_an_unprivileged_test_refuses() {
        let argv = [
            OsString::from("xudo-session"),
            OsString::from("record"),
            OsString::from("codex"),
        ];
        let exit = run(&argv);
        // Neither root nor a child of pid 1 here, whatever else the host has.
        assert_eq!(exit.status, 1);
        assert!(exit.message.starts_with("xudo-session: refused"));
        assert_eq!(run(&[]).status, 2);
    }

    #[test]
    fn the_opened_cgroup_seam_is_handed_over_as_a_trait_object() {
        let opened: Result<Cgroups, SysError> = Ok(Cgroups::in_unit(UNIT_PATH));
        let calls = cgroups_seam(&opened).unwrap();
        assert!(calls.require_cgroup2().is_ok());
        let stream = std::os::unix::net::UnixStream::pair().unwrap().0;
        let fd = std::os::fd::AsFd::as_fd(&stream);
        assert!(calls.pidfd_cgroup_id(fd).is_err());
        assert_eq!(calls.peer_alive(fd), Ok(true));
        assert_eq!(calls.scope_names(), Ok(Vec::new()));
        let failed: Result<Cgroups, SysError> = Err(SysError::unsupported("cgroup2"));
        assert!(cgroups_seam(&failed).is_err());
    }

    #[test]
    fn exit_statuses_distinguish_a_bad_command_line_from_a_refusal() {
        assert_eq!(UnitRecordError::Usage.status(), 2);
        for error in [
            UnitRecordError::NotRoot,
            UnitRecordError::NotFromInit,
            UnitRecordError::UnitUntrusted,
            UnitRecordError::Invalid,
        ] {
            assert_eq!(error.status(), 1);
        }
    }
}
