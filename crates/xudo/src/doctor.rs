//! `xudo doctor`: what this machine is, what xudo can rely on here, and every
//! other way to root that would make xudo decorative.
//!
//! Everything is gathered once into a [`Report`] and then rendered, as prose
//! for a person or as a versioned envelope for a program. Both come from the
//! same value, so they cannot disagree about what was found.
//!
//! # The envelope
//!
//! [`DOCTOR_SCHEMA_VERSION`], then stable `snake_case` field names: the
//! platform and kernel, the ruleset and whether it is root's, how this caller
//! is classified, the backend with its implementation and every probed
//! capability (also for a backend xudo refuses, so an operator sees which
//! control is missing), the other paths to root it can check, and the proposals when
//! `--fix` asked for them (`null` when it did not). A field is added, never
//! renamed; a change in meaning is a new schema version. The snapshots in this
//! module pin it.
//!
//! # `--fix` applies nothing
//!
//! It prints each proposal, what accepting it means, and the exact command a
//! human runs, and it changes nothing. That is a decision, not a gap:
//!
//! * Applying would mean reading a yes from this process's terminal, and a
//!   confirmation read from the requester's own terminal is one an agent
//!   driving that terminal can type.
//! * Applying would mean running `sudo` from inside xudo, and `sudo` may not
//!   ask: a credential cached by an earlier command, or a standing `NOPASSWD`
//!   rule — one of the very things this report finds — would let an agent
//!   that runs `xudo doctor --fix` make a privilege change no human saw.
//!
//! Printed, the command is run by a human in a shell they started, where the
//! backend asks for their password: on the password path, the password is the
//! confirmation. This function takes no input stream at all, so there is
//! nothing here that could read one.
//!
//! # What a terminal is shown
//!
//! Paths, rule text, and names come from the machine, and a world-writable
//! directory lets anyone choose a file name. Every such string goes through
//! `term-sanitize` on its way to the terminal, flagged when anything was
//! removed. The `--json` envelope is ASCII: every other character, DEL and the
//! C1 controls included, is a `\uXXXX` escape. Every command argument is quoted
//! for the shell (the proposals only carry printable ASCII without a
//! backslash; anything else is a by-hand instruction).

use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use term_sanitize::Limits;
use xudo_backend::paths_to_root::{
    self, Applies, Check, CheckId, Finding, Grant, Input, Proposal, Status, Unverified, Via,
    Writer, assess, propose,
};
use xudo_backend::{Backend, BackendKind, Capability, DetectError, identify, judge};
use xudo_policy::{CallerFacts, ExitCode};
use xudo_sys::{HostRunner, KernelSupport, Runner, SysError, TrustError, TrustedFile};

use crate::cli::Platform;
use crate::render;
use crate::rules::{LoadError, LoadedRules};

/// The version of the `doctor --json` envelope.
pub const DOCTOR_SCHEMA_VERSION: u32 = 1;

/// How much of one machine-derived string a terminal is shown.
const LIMITS: Limits = Limits {
    max_cols: 512,
    max_lines: 1,
};

/// Everything `doctor` reports.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// [`DOCTOR_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The xudo that wrote this.
    pub xudo_version: &'static str,
    /// Which platform implementation answered.
    pub platform: &'static str,
    /// What `xudo exec` would run: the backend, or why there is none.
    pub exec_path: String,
    /// What the kernel offers the broker.
    pub kernel: KernelReport,
    /// The ruleset, and whether it is root's.
    pub ruleset: RulesetReport,
    /// Whether xudo's sudoers rule is installed under a name sudo reads.
    pub sudoers_snippet: SnippetReport,
    /// How this caller is classified.
    pub caller: CallerReport,
    /// The privilege backend.
    pub backend: BackendReport,
    /// Every other path to root.
    pub paths_to_root: paths_to_root::Report,
    /// What `--fix` proposes; `None` when it was not asked.
    pub proposals: Option<Vec<Proposal>>,
}

/// What the kernel offers the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KernelReport {
    /// The version read, or `unknown`.
    pub version: String,
    /// The mechanism the broker identifies its peer by.
    pub attestation: &'static str,
    /// The first kernel with it.
    pub attestation_since: String,
    /// Whether an agent can ever be authorised without a password here.
    pub agent_path_available: bool,
    /// Why not, when it cannot.
    pub withheld_because: Option<&'static str>,
    /// How a path is opened without giving a link a chance to move.
    pub resolution: &'static str,
    /// The line the prose report prints.
    pub summary: String,
}

impl KernelReport {
    fn of(support: KernelSupport) -> Self {
        Self {
            version: support.version.to_string(),
            attestation: support.attestation.mechanism(),
            attestation_since: support.attestation.since().to_string(),
            agent_path_available: support.agent_path_available(),
            withheld_because: support.attestation.withheld_because(),
            resolution: support.resolution.mechanism(),
            summary: if support.agent_path_available() {
                format!(
                    "{} via {} (kernel supports attestation for the planned agent path; agent path not in this build)",
                    support.version,
                    support.attestation.mechanism()
                )
            } else {
                support.summary()
            },
        }
    }
}

/// The ruleset, and whether it is root's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RulesetReport {
    /// The directory named by `--rules`.
    pub dir: String,
    /// What was loaded from it, when it loaded.
    pub loaded: Option<LoadedSummary>,
    /// Why it did not load, when it did not.
    pub load_error: Option<String>,
    /// Whether it is root's, checked the way the gate must load it.
    pub trust: TrustReport,
    /// Whether each loaded rule matches dpkg's shipped conffile checksum.
    pub package_drift: RuleDriftReport,
    /// Set when the rules loaded and none of them is `xudo.svc.lifecycle`.
    ///
    /// A note, not a fault: doctor still exits 0. Absent when the rules did
    /// not load, and when the operator has copied the example.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_note: Option<&'static str>,
    /// Systemctl rules that can start or stop a unit they do not name.
    ///
    /// A fault in the report, and `xudo check` exits 21 for the same rules.
    /// Absent when the rules did not load or every unit matcher is a finite list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_unit_lints: Vec<OpenUnitLintRow>,
}

/// One systemctl rule whose unit matcher is not a finite list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OpenUnitLintRow {
    /// The action id.
    pub action: String,
    /// The rule file.
    pub file: String,
    /// The 1-based line of the action.
    pub line: u32,
    /// The sentence check prints, including the id and the `file:line`.
    pub message: String,
}

/// How a loaded rule relates to dpkg's original conffile record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDriftStatus {
    /// Current bytes have the checksum dpkg recorded for the package.
    MatchesShipped,
    /// dpkg retained a conffile that a later package version stopped shipping.
    NoLongerShipped,
    /// A package conffile whose current bytes differ.
    ChangedLocally,
    /// No dpkg conffile record names this file.
    NotFromPackage,
    /// The package record or a trusted current read was unavailable.
    Unknown,
}

/// Package provenance for the files this ruleset loaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleDriftReport {
    /// One row for every loaded rule file.
    pub files: Vec<RuleDriftRow>,
    /// Why package comparison could not be completed, if applicable.
    pub unavailable: Option<String>,
}

/// One loaded rule file's package provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleDriftRow {
    /// The rule's path.
    pub path: String,
    /// The comparison result.
    pub status: RuleDriftStatus,
}

/// sudo's treatment of xudo's own snippet and marked copies it ignores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnippetReport {
    /// Whether the canonical extensionless `/etc/sudoers.d/xudo` is managed.
    pub installed_rule: Option<bool>,
    /// Marked snippets under names sudo skips.
    pub not_in_effect: Vec<String>,
    /// Why sudo ignores those names.
    pub ignored_reason: &'static str,
    /// Why the directory or a trusted file could not be checked.
    pub unavailable: Option<String>,
}

/// A loaded ruleset, in brief.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoadedSummary {
    /// How many actions.
    pub actions: usize,
    /// How many files.
    pub files: usize,
    /// The policy generation, all 64 hex characters.
    pub generation: String,
}

/// Whether the ruleset, and every rule file in it, belongs to root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustReport {
    /// Every component opened through its parent's descriptor without
    /// following a link, and every rule file checked on its own descriptor.
    pub trusted: bool,
    /// How many rule files were checked, when it is trusted.
    pub files_checked: Option<usize>,
    /// The first component that failed, and why, when it is not.
    pub reason: Option<String>,
}

/// How this caller is classified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CallerReport {
    /// The classification, when the caller could be observed.
    pub classification: Option<&'static str>,
    /// Whether the backend will ask this caller for a password.
    pub password_required: bool,
    /// Unauthenticated hints recorded for the audit trail.
    pub hints_recorded: usize,
    /// Hints that decided anything: zero, by construction.
    pub hints_trusted: usize,
    /// Why the caller could not be observed, when it could not.
    pub unavailable: Option<String>,
}

/// Whether xudo can use the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendStatus {
    /// Every required capability is present.
    Usable,
    /// One is missing, and xudo refuses to install over it.
    Unusable,
    /// There is no backend at all.
    None,
}

/// The privilege backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackendReport {
    /// Whether xudo can use it.
    pub status: BackendStatus,
    /// `sudo`, `sudo-rs`, or `doas`.
    pub implementation: Option<BackendKind>,
    /// Where it was found.
    pub exe: Option<String>,
    /// Its version banner's first line, empty when it printed none.
    pub version: Option<String>,
    /// Every capability, probed, whether or not the backend has it.
    pub capabilities: Vec<CapabilityRow>,
    /// The required capabilities it lacks.
    pub missing_required: Vec<Capability>,
    /// Why xudo cannot use it, when it cannot.
    pub refusal: Option<String>,
}

/// One probed capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityRow {
    /// Which.
    pub capability: Capability,
    /// Whether the backend was found to support it.
    pub supported: bool,
    /// Whether xudo refuses to operate without it.
    pub required: bool,
}

impl BackendReport {
    fn of(identified: Option<Backend>) -> Self {
        let Some(backend) = identified else {
            return Self {
                status: BackendStatus::None,
                implementation: None,
                exe: None,
                version: None,
                capabilities: Vec::new(),
                missing_required: Vec::new(),
                refusal: Some(DetectError::NoBackend.to_string()),
            };
        };
        let refusal = judge(backend.clone()).err().map(|error| error.to_string());
        Self {
            status: if refusal.is_some() {
                BackendStatus::Unusable
            } else {
                BackendStatus::Usable
            },
            implementation: Some(backend.kind),
            capabilities: Capability::ALL
                .into_iter()
                .map(|capability| CapabilityRow {
                    capability,
                    supported: backend.capabilities.has(capability),
                    required: capability.is_required(),
                })
                .collect(),
            missing_required: backend.capabilities.missing_required(),
            exe: Some(backend.exe),
            version: Some(backend.version),
            refusal,
        }
    }
}

/// Gathers the whole report from a platform.
pub(crate) fn gather(
    rules: &Path,
    loaded: Result<&LoadedRules, &LoadError>,
    platform: &Platform<'_>,
    fix: bool,
) -> Report {
    let backend = identify(platform.probe);
    let backend_exe = backend.as_ref().map(|found| Path::new(found.exe.as_str()));
    let paths = assess(
        platform.host,
        &Input {
            user_path: platform.path,
            backend_exe,
            sudo_exe: backend
                .as_ref()
                .filter(|found| matches!(found.kind, BackendKind::Sudo | BackendKind::SudoRs))
                .map(|found| found.exe.as_str()),
            doas_exe: backend
                .as_ref()
                .filter(|found| matches!(found.kind, BackendKind::Doas))
                .map(|found| found.exe.as_str()),
        },
    );
    // Root commands go through the backend, where the human types their
    // password; a root caller needs no prefix.
    let prefix = backend
        .as_ref()
        .map(|found| found.exe.as_str())
        .filter(|_| !paths.subject.is_root);
    let proposals = fix.then(|| propose(platform.host, &paths, prefix));
    Report {
        schema_version: DOCTOR_SCHEMA_VERSION,
        xudo_version: env!("CARGO_PKG_VERSION"),
        platform: platform.ops.platform(),
        exec_path: backend.as_ref().map_or_else(
            || "no backend; `xudo exec` exits 19".to_owned(),
            |found| format!("xudo exec runs {} on the gate", found.exe),
        ),
        kernel: KernelReport::of(platform.ops.kernel()),
        ruleset: ruleset(rules, loaded),
        sudoers_snippet: sudoers_snippets(),
        caller: caller(platform.ops.classify(std::process::id())),
        backend: BackendReport::of(backend),
        paths_to_root: paths,
        proposals,
    }
}

/// Runs `doctor`.
pub(crate) fn run(
    rules: &Path,
    loaded: Result<&LoadedRules, &LoadError>,
    platform: &Platform<'_>,
    json: bool,
    fix: bool,
    out: &mut dyn Write,
) -> ExitCode {
    let report = gather(rules, loaded, platform, fix);
    let text = if json {
        format!("{}\n", render::json_of(&report))
    } else {
        human(&report)
    };
    let _ = out.write_all(text.as_bytes());
    // Diagnostic: what it found is in the report, for a person to read or a
    // program to branch on, and asking was not a failure.
    ExitCode::Delegated
}

/// The ruleset section, with the trust walk the gate must use.
///
/// Reported here rather than enforced here. `doctor` is diagnostic, and the
/// enforcement point is the executor: a check the front-end could "pass"
/// would be a check an attacker races against.
fn ruleset(rules: &Path, loaded: Result<&LoadedRules, &LoadError>) -> RulesetReport {
    let trusted = xudo_sys::read_trusted_dir(rules);
    let trust = trust_report(&trusted);
    let package_drift = rule_drift(rules, loaded, &trusted);
    RulesetReport {
        dir: rules.display().to_string(),
        loaded: loaded.ok().map(|loaded| LoadedSummary {
            actions: loaded.rules().len(),
            files: loaded.files().len(),
            generation: loaded.generation().to_owned(),
        }),
        load_error: loaded.err().map(ToString::to_string),
        trust,
        package_drift,
        lifecycle_note: loaded.ok().and_then(|loaded| {
            crate::lifecycle_note::missing(loaded.rules()).then_some(crate::lifecycle_note::TEXT)
        }),
        open_unit_lints: loaded
            .ok()
            .map(|loaded| {
                loaded
                    .rules()
                    .open_unit_actions()
                    .iter()
                    .map(|lint| OpenUnitLintRow {
                        action: lint.id.to_string(),
                        file: lint.source.file.clone(),
                        line: lint.source.line,
                        message: lint.message(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn rule_drift(
    rules: &Path,
    loaded: Result<&LoadedRules, &LoadError>,
    trusted: &Result<Vec<TrustedFile>, TrustError>,
) -> RuleDriftReport {
    let Ok(loaded) = loaded else {
        return RuleDriftReport {
            files: Vec::new(),
            unavailable: Some("rules did not load".to_owned()),
        };
    };
    let trusted = match trusted {
        Ok(files) => files,
        Err(error) => return unavailable_drift(loaded.files(), error.to_string()),
    };
    rule_drift_from_trusted(rules, loaded.files(), trusted, &HostRunner)
}

fn unavailable_drift(paths: &[PathBuf], reason: String) -> RuleDriftReport {
    RuleDriftReport {
        files: paths
            .iter()
            .map(|path| RuleDriftRow {
                path: path.display().to_string(),
                status: RuleDriftStatus::Unknown,
            })
            .collect(),
        unavailable: Some(reason),
    }
}

fn rule_drift_from_trusted(
    rules: &Path,
    paths: &[PathBuf],
    trusted: &[TrustedFile],
    runner: &dyn Runner,
) -> RuleDriftReport {
    let query = match runner.run(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${Conffiles}\\n", "xudo"],
        None,
    ) {
        Ok(output) if output.success => output.stdout,
        Ok(_) => {
            return unavailable_drift(paths, "dpkg-query could not read xudo conffiles".to_owned());
        }
        Err(error) => return unavailable_drift(paths, error.to_string()),
    };
    let records = parse_conffiles(&query);
    let mut files = Vec::with_capacity(paths.len());
    let mut unavailable = None;
    for path in paths {
        let Some(name) = path.file_name() else {
            files.push(RuleDriftRow {
                path: path.display().to_string(),
                status: RuleDriftStatus::Unknown,
            });
            unavailable.get_or_insert_with(|| "loaded rule has no file name".to_owned());
            continue;
        };
        let full_path = rules.join(name);
        let Some(current) = trusted.iter().find(|file| file.name.as_os_str() == name) else {
            files.push(RuleDriftRow {
                path: full_path.display().to_string(),
                status: RuleDriftStatus::Unknown,
            });
            unavailable.get_or_insert_with(|| {
                "trusted rule read did not include every loaded file".to_owned()
            });
            continue;
        };
        let Some(record) = records.get(full_path.as_os_str().as_bytes()) else {
            files.push(RuleDriftRow {
                path: full_path.display().to_string(),
                status: RuleDriftStatus::NotFromPackage,
            });
            continue;
        };
        if record.status == ConffileStatus::Obsolete {
            files.push(RuleDriftRow {
                path: full_path.display().to_string(),
                status: RuleDriftStatus::NoLongerShipped,
            });
            continue;
        }
        if record.status == ConffileStatus::New {
            files.push(RuleDriftRow {
                path: full_path.display().to_string(),
                status: RuleDriftStatus::Unknown,
            });
            unavailable
                .get_or_insert_with(|| "dpkg reports a new conffile without a baseline".to_owned());
            continue;
        }
        let digest = match runner.run("/usr/bin/md5sum", &[], Some(&current.bytes)) {
            Ok(output) if output.success => output
                .stdout
                .split_ascii_whitespace()
                .next()
                .map(str::to_owned),
            _ => None,
        };
        let status = match digest {
            Some(digest) if digest.eq_ignore_ascii_case(&record.digest) => {
                RuleDriftStatus::MatchesShipped
            }
            Some(_) => RuleDriftStatus::ChangedLocally,
            None => {
                unavailable
                    .get_or_insert_with(|| "md5sum could not hash a trusted rule file".to_owned());
                RuleDriftStatus::Unknown
            }
        };
        files.push(RuleDriftRow {
            path: full_path.display().to_string(),
            status,
        });
    }
    RuleDriftReport { files, unavailable }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConffileStatus {
    Shipped,
    Obsolete,
    New,
}

struct ConffileRecord {
    digest: String,
    status: ConffileStatus,
}

/// One `${Conffiles}` line, as dpkg prints it: a leading space, the path, then
/// either 32 lowercase hex digits or the word `newconffile` in place of them,
/// then only `obsolete` and `remove-on-upgrade`. `newconffile` is not a flag
/// after a hash. The path is the original prefix, so a doubled space or a tab
/// in it stays; a flag word that is part of the path stays too.
fn parse_conffiles(output: &str) -> std::collections::BTreeMap<Vec<u8>, ConffileRecord> {
    output.lines().filter_map(parse_conffile_line).collect()
}

fn parse_conffile_line(line: &str) -> Option<(Vec<u8>, ConffileRecord)> {
    let mut rest = line.trim_ascii_end();
    let mut obsolete = false;
    let (prefix, token) = loop {
        let (prefix, token) = rest.rsplit_once(|byte: char| byte.is_ascii_whitespace())?;
        if token == "obsolete" || token == "remove-on-upgrade" {
            obsolete = true;
            rest = prefix.trim_ascii_end();
            continue;
        }
        break (prefix, token);
    };
    let (digest, status) = if is_lowercase_md5(token) {
        let status = if obsolete {
            ConffileStatus::Obsolete
        } else {
            ConffileStatus::Shipped
        };
        (token.to_owned(), status)
    } else if token == "newconffile" {
        (String::new(), ConffileStatus::New)
    } else {
        return None;
    };
    let path = prefix.strip_prefix(' ')?;
    if !path.starts_with('/') {
        return None;
    }
    Some((path.as_bytes().to_vec(), ConffileRecord { digest, status }))
}

fn is_lowercase_md5(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn sudoers_snippets() -> SnippetReport {
    sudoers_snippets_at(Path::new("/etc/sudoers.d"), &read_sudoers_candidate)
}

type SudoersReader = dyn Fn(&Path) -> Result<Option<Vec<u8>>, String>;

fn read_sudoers_candidate(path: &Path) -> Result<Option<Vec<u8>>, String> {
    read_sudoers_candidate_with(path, &|path| {
        xudo_sys::read_trusted_file(path, 1 << 20).map_err(|error| error.to_string())
    })
}

fn read_sudoers_candidate_with(
    path: &Path,
    read_file: &SudoersReader,
) -> Result<Option<Vec<u8>>, String> {
    read_file(path)
}

fn sudoers_snippets_at(dir: &Path, read_file: &SudoersReader) -> SnippetReport {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => Ok(entries
            .map(|entry| map_sudoers_entry(entry, read_file))
            .collect()),
        Err(error) => Err(error.to_string()),
    };
    summarize_sudoers_scan(entries, &dir.join("xudo"))
}

fn map_sudoers_entry(
    entry: std::io::Result<std::fs::DirEntry>,
    read_file: &SudoersReader,
) -> SudoersEntry {
    match entry {
        Ok(entry) => SudoersEntry::File {
            path: entry.path(),
            bytes: read_file(&entry.path()),
        },
        Err(error) => SudoersEntry::Error(error.to_string()),
    }
}

enum SudoersEntry {
    File {
        path: PathBuf,
        bytes: Result<Option<Vec<u8>>, String>,
    },
    Error(String),
}

fn summarize_sudoers_scan(
    entries: Result<Vec<SudoersEntry>, String>,
    installed: &Path,
) -> SnippetReport {
    const MARKER: &[u8] = xudo_backend::snippet::MANAGED_MARKER.as_bytes();
    const IGNORED_REASON: &str = "sudo skips filenames containing a dot or ending in ~";
    let entries = match entries {
        Ok(entries) => entries,
        Err(reason) => {
            return SnippetReport {
                installed_rule: None,
                not_in_effect: Vec::new(),
                ignored_reason: IGNORED_REASON,
                unavailable: Some(reason),
            };
        }
    };
    let mut marked_entries = Vec::new();
    let mut unavailable = None;
    let mut canonical_checked = true;
    for entry in entries {
        let (path, bytes) = match entry {
            SudoersEntry::File { path, bytes } => (path, bytes),
            SudoersEntry::Error(reason) => {
                unavailable.get_or_insert(reason);
                canonical_checked = false;
                continue;
            }
        };
        let bytes = match bytes {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                if path == installed {
                    canonical_checked = false;
                }
                continue;
            }
            Err(reason) => {
                unavailable.get_or_insert(reason);
                if path == installed {
                    canonical_checked = false;
                }
                continue;
            }
        };
        marked_entries.push((path, bytes.starts_with(MARKER)));
    }
    let installed_rule = canonical_checked.then(|| {
        marked_entries
            .iter()
            .find(|(path, _)| path == installed)
            .is_some_and(|(_, marked)| *marked)
    });
    let mut not_in_effect: Vec<String> = marked_entries
        .iter()
        .filter(|(path, marked)| {
            *marked
                && path
                    .file_name()
                    .is_some_and(|name| snippet_name_is_ignored(name.as_bytes()))
        })
        .map(|(path, _)| path.display().to_string())
        .collect();
    not_in_effect.sort();
    SnippetReport {
        installed_rule,
        not_in_effect,
        ignored_reason: IGNORED_REASON,
        unavailable,
    }
}

fn snippet_name_is_ignored(filename: &[u8]) -> bool {
    filename.contains(&b'.') || filename.ends_with(b"~")
}

/// The trust walk's outcome as a report.
///
/// Split out so both outcomes are reachable from a test on every platform: off
/// Linux there is no mount table, so the walk itself can never succeed there.
pub(crate) fn trust_report(
    outcome: &Result<Vec<xudo_sys::TrustedFile>, xudo_sys::TrustError>,
) -> TrustReport {
    match outcome {
        Ok(files) => TrustReport {
            trusted: true,
            files_checked: Some(files.len()),
            reason: None,
        },
        Err(source) => TrustReport {
            trusted: false,
            files_checked: None,
            reason: Some(source.to_string()),
        },
    }
}

/// The caller section. An unobservable caller still gets an answer, and it
/// is the password-requiring one.
fn caller(classified: Result<CallerFacts, SysError>) -> CallerReport {
    match classified {
        Ok(facts) => CallerReport {
            classification: Some(facts.classification.label()),
            password_required: facts.classification.requires_password(),
            hints_recorded: facts.hints.len(),
            hints_trusted: 0,
            unavailable: None,
        },
        Err(error) => CallerReport {
            classification: None,
            password_required: true,
            hints_recorded: 0,
            hints_trusted: 0,
            unavailable: Some(error.to_string()),
        },
    }
}

/// The report as prose.
pub(crate) fn human(report: &Report) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        let _ = writeln!(out, "{label:<12} {value}");
    };
    line("platform", report.platform);
    line("kernel", &safe(&report.kernel.summary));
    line("rules dir", &safe(&report.ruleset.dir));
    line(
        "ruleset",
        &report.ruleset.loaded.as_ref().map_or_else(
            || "NOT LOADED (run `xudo check` for the parse error)".to_owned(),
            |loaded| {
                format!(
                    "{} action(s), {} file(s), generation {}",
                    loaded.actions,
                    loaded.files,
                    loaded.generation.get(..12).unwrap_or_default()
                )
            },
        ),
    );
    line("rules trust", &trust_line(&report.ruleset.trust));
    for row in &report.ruleset.package_drift.files {
        line(
            "rule package",
            &format!("{}: {}", safe(&row.path), drift_label(row.status)),
        );
    }
    if let Some(reason) = &report.ruleset.package_drift.unavailable {
        line("rule package", &format!("unknown: {}", safe(reason)));
    }
    if report.backend.implementation == Some(BackendKind::Doas) {
        line("sudoers xudo", "does not apply to the doas backend");
    } else {
        match report.sudoers_snippet.installed_rule {
            Some(true) => line("sudoers xudo", "managed rule at /etc/sudoers.d/xudo"),
            Some(false) => line(
                "sudoers xudo",
                "no xudo rule installed at /etc/sudoers.d/xudo",
            ),
            None => line("sudoers xudo", "unknown: canonical rule could not be read"),
        }
    }
    for path in &report.sudoers_snippet.not_in_effect {
        line(
            "sudoers xudo",
            &format!(
                "{} is not in effect: {}",
                safe(path),
                report.sudoers_snippet.ignored_reason
            ),
        );
    }
    if report.backend.implementation != Some(BackendKind::Doas) {
        if let Some(reason) = &report.sudoers_snippet.unavailable {
            line("sudoers xudo", &format!("unknown: {}", safe(reason)));
        }
    }
    if let Some(label) = report.caller.classification {
        line("classified", label);
        line(
            "password",
            if report.caller.password_required {
                "required"
            } else {
                "not required"
            },
        );
        line(
            "hints",
            &format!("{} recorded, 0 trusted", report.caller.hints_recorded),
        );
    } else {
        line(
            "classified",
            &format!(
                "unavailable: {}",
                safe(report.caller.unavailable.as_deref().unwrap_or_default())
            ),
        );
        line("password", "required (failing closed)");
    }
    backend_lines(&report.backend, &mut line);
    line("exec path", &report.exec_path);
    // `line` borrows `out` until here. The helper writes before the trust row.
    insert_ruleset_notes(
        &mut out,
        report.ruleset.lifecycle_note,
        &report.ruleset.open_unit_lints,
    );
    let _ = write!(out, "{}", paths_section(&report.paths_to_root));
    if let Some(proposals) = &report.proposals {
        let prefixed = report.backend.exe.is_some() && !report.paths_to_root.subject.is_root;
        let _ = write!(out, "{}", proposals_section(proposals, prefixed));
    }
    let _ = writeln!(
        out,
        "\nThis build performs no privileged operation. Agent detection is not a\n\
         security boundary; the allowlist and the compiled-in deny-list are."
    );
    out
}

/// Puts the lifecycle note and any open-unit lints before the rules-trust row.
///
/// `human` cannot write them there directly: the row closure borrows the
/// buffer until the last row. No anchor means the ruleset section was not
/// rendered, and the lines are omitted rather than appended somewhere else.
fn insert_ruleset_notes(out: &mut String, note: Option<&str>, lints: &[OpenUnitLintRow]) {
    if note.is_none() && lints.is_empty() {
        return;
    }
    let Some(pos) = out.find("\nrules trust") else {
        return;
    };
    let mut block = String::new();
    if let Some(note) = note {
        block.push_str(note);
        block.push('\n');
    }
    for lint in lints {
        block.push_str(&safe(&lint.message));
        block.push('\n');
    }
    // One past the newline that opens the trust row. Display layout only.
    let at = pos.saturating_add(1);
    out.insert_str(at, &block);
}

fn drift_label(status: RuleDriftStatus) -> &'static str {
    match status {
        RuleDriftStatus::MatchesShipped => "matches shipped",
        RuleDriftStatus::NoLongerShipped => "no longer shipped",
        RuleDriftStatus::ChangedLocally => "changed locally",
        RuleDriftStatus::NotFromPackage => "not from the package",
        RuleDriftStatus::Unknown => "unknown",
    }
}

/// The trust line, saying which situation it is rather than a bare FAIL: a
/// development checkout is expected to fail this. The walk checks every
/// component through its parent's descriptor, every rule file on its own, and
/// the mount under each in the mount table; a refused mount names the
/// component, the filesystem, and why.
pub(crate) fn trust_line(trust: &TrustReport) -> String {
    match &trust.reason {
        Some(reason) => format!("UNTRUSTED: {}", safe(reason)),
        None => format!(
            "root-owned, no writable component, no user-made mount; {} rule file(s) checked on \
             their descriptors",
            trust.files_checked.unwrap_or_default()
        ),
    }
}

/// The backend lines, in the form the differential matrix reads.
///
/// A count and then one line per absent capability, with no "all present"
/// case: 7 of 7 is not reachable for any real backend.
fn backend_lines(backend: &BackendReport, line: &mut dyn FnMut(&str, &str)) {
    match backend.status {
        BackendStatus::None => {
            line("backend", "NONE — xudo cannot operate on this machine");
            line(
                "",
                "xudo delegates every uid transition and performs none itself",
            );
        }
        BackendStatus::Unusable => {
            line(
                "backend",
                &format!(
                    "UNUSABLE: {}",
                    safe(backend.refusal.as_deref().unwrap_or_default())
                ),
            );
        }
        BackendStatus::Usable => {
            let version = safe(backend.version.as_deref().unwrap_or_default());
            line(
                "backend",
                &format!(
                    "{} ({})",
                    backend.implementation.map_or("", BackendKind::label),
                    if version.is_empty() {
                        "no version banner"
                    } else {
                        &version
                    }
                ),
            );
            let supported = backend.capabilities.iter().filter(|row| row.supported);
            line(
                "backend caps",
                &format!(
                    "{} of {} supported",
                    supported.count(),
                    backend.capabilities.len()
                ),
            );
            for row in backend.capabilities.iter().filter(|row| !row.supported) {
                line("", &format!("absent: {}", capability_label(row.capability)));
            }
        }
    }
}

/// A short name for a capability, for the prose report.
pub(crate) fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::DropInDirectory => "drop-in directory",
        Capability::ValidateNamedFile => "validate named file",
        Capability::PerCommandDefaults => "per-command defaults (REQUIRED)",
        Capability::DisableCredentialCache => "disable credential cache (REQUIRED)",
        Capability::AllocatePty => "allocate pty (REQUIRED)",
        Capability::RejectsArgumentWildcards => "rejects argument wildcards",
        Capability::PersistentCredentialCache => "persistent credential cache",
    }
}

/// Every other path to root, as prose.
fn paths_section(report: &paths_to_root::Report) -> String {
    let mut out = String::new();
    let who = report.subject.name.as_deref().map_or_else(
        || format!("uid {}", report.subject.uid),
        |name| format!("{} (uid {})", safe(name), report.subject.uid),
    );
    let mut summary = match report.finding_count() {
        0 => "none found".to_owned(),
        found => format!("{found} found"),
    };
    let incomplete = report.unverified_count();
    if incomplete > 0 {
        let _ = write!(
            summary,
            ", and {incomplete} check(s) could not be completed"
        );
    }
    let _ = writeln!(out, "\nother paths to root, as {who}: {summary}");
    let _ = writeln!(
        out,
        "  any one of these is a way to root that does not go through xudo"
    );
    for check in &report.checks {
        check_lines(&mut out, check);
    }
    let group = report.xudo_group;
    let membership = match (group.exists, group.member) {
        (false, _) => "does not exist here: nobody can ask xudo for anything yet".to_owned(),
        (true, true) => format!(
            "exists (gid {}); you are in it",
            group.gid.unwrap_or_default()
        ),
        (true, false) => format!(
            "exists (gid {}); you are not in it, and `xudo doctor --fix` shows how to join",
            group.gid.unwrap_or_default()
        ),
    };
    let _ = writeln!(out, "  {:<21} {membership}", "xudo group");
    if incomplete > 0 && !report.subject.is_root {
        let _ = writeln!(
            out,
            "  unverified is not clean: run `sudo xudo doctor` to read what this account \
             cannot, and keep this run for the checks that only mean something as you"
        );
    }
    out
}

/// One check, its findings, what it could not see, and its note.
fn check_lines(out: &mut String, check: &Check) {
    let examined = if check.status == Status::Skipped {
        String::new()
    } else {
        format!(", {} examined", check.examined)
    };
    let _ = writeln!(
        out,
        "  {:<21} {}{examined}",
        check_label(check.check),
        status_word(check.status),
    );
    for finding in &check.findings {
        let _ = writeln!(out, "    {}", finding_line(finding));
    }
    for gap in &check.unverified {
        let _ = writeln!(out, "    {}", unverified_line(gap));
    }
    if let Some(note) = &check.note {
        let _ = writeln!(out, "    note: {}", safe(note));
    }
}

/// What a check is called in prose.
fn check_label(check: CheckId) -> &'static str {
    match check {
        CheckId::PasswordlessRules => "passwordless rules",
        CheckId::GroupMemberships => "group memberships",
        CheckId::UnitDirectories => "unit directories",
        CheckId::RootPath => "root's PATH",
        CheckId::UserPath => "your PATH",
        CheckId::RootShellStartup => "root's shell startup",
    }
}

/// A status in prose: the two that need attention in capitals.
fn status_word(status: Status) -> &'static str {
    match status {
        Status::Skipped => "skipped",
        Status::Clean => "clean",
        Status::Unverified => "UNVERIFIED",
        Status::Found => "FOUND",
    }
}

/// One finding, as one line.
fn finding_line(finding: &Finding) -> String {
    match finding {
        Finding::PasswordlessRule {
            file,
            line,
            text,
            grant,
            applies_to_you,
        } => format!(
            "{}:{line} {} ({}): {}",
            safe_path(file),
            match grant {
                Grant::Nopasswd => "NOPASSWD",
                Grant::NoAuthenticate => "!authenticate",
                Grant::Nopass => "nopass",
                Grant::Include => "include",
            },
            match applies_to_you {
                Applies::Yes => "names you",
                Applies::Maybe => "may name you",
                Applies::No => "names others",
            },
            safe(text)
        ),
        Finding::BackendListing { user, listing } => format!(
            "sudo itself lists a rule for {} that needs no password: {}",
            safe(user),
            safe(&listing.replace('\n', " | "))
        ),
        Finding::DoasNopass { command, file } => format!(
            "doas itself permits {} for you without a password, by {}",
            safe(command),
            safe_path(file)
        ),
        Finding::GroupMembership {
            group,
            gid,
            grants,
            listed,
            active,
            ..
        } => {
            let how = if *listed && *active {
                "listed in /etc/group and held now"
            } else if *listed {
                "listed in /etc/group, held from your next login"
            } else {
                "held by this session, not listed in /etc/group"
            };
            format!("{group} (gid {gid}), {how}: {grants}")
        }
        Finding::Writable {
            path,
            at,
            via,
            writers,
            shadows,
        } => {
            let who = writers_phrase(writers);
            let mut line = match via {
                Via::Itself => format!("{} is writable by {who}", safe_path(path)),
                Via::Ancestor => format!(
                    "{}: {}, above it, is writable by {who}",
                    safe_path(path),
                    safe_path(at)
                ),
                Via::Missing => format!(
                    "{} does not exist, and {}, where it would be created, is writable by {who}",
                    safe_path(path),
                    safe_path(at)
                ),
            };
            if let Some(backend) = shadows {
                let _ = write!(
                    line,
                    "; it comes before {}, so whatever is put there is found first",
                    safe(backend)
                );
            }
            line
        }
        Finding::RelativePathEntry { entry } => format!(
            "\"{}\" is a relative entry, looked up in whatever directory the shell is in",
            safe_path(entry)
        ),
    }
}

/// Who can write something, in prose.
fn writers_phrase(writers: &[Writer]) -> String {
    writers
        .iter()
        .map(|writer| match writer {
            Writer::You => "you, by an ACL or a capability the mode bits do not show".to_owned(),
            Writer::Owner { you: true, .. } => "its owner, you".to_owned(),
            Writer::Owner { uid, name, .. } => match name {
                Some(name) => format!("its owner, {} (uid {uid})", safe(name)),
                None => format!("its owner, uid {uid}"),
            },
            Writer::Group { gid, name, you } => format!(
                "{}{}",
                match name {
                    Some(name) => format!("the group {} (gid {gid})", safe(name)),
                    None => format!("the group with gid {gid}"),
                },
                if *you { ", which you are in" } else { "" }
            ),
            Writer::Everyone => "everyone".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", and by ")
}

/// Something a check could not examine, as one line.
fn unverified_line(gap: &Unverified) -> String {
    if gap.at == gap.path {
        format!(
            "cannot verify {}: {}",
            safe_path(&gap.path),
            safe(&gap.reason)
        )
    } else {
        format!(
            "cannot verify {} ({}): {}",
            safe_path(&gap.path),
            safe_path(&gap.at),
            safe(&gap.reason)
        )
    }
}

/// The proposals, as prose. `prefixed` says whether root commands carry the
/// backend in front of them, or are for a shell that is root already.
fn proposals_section(proposals: &[Proposal], prefixed: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nproposed fixes: xudo applies none of them. Each is for a human to run, in a shell \
         they started;\n{}",
        if prefixed {
            "a command that needs root starts with the backend, which asks for their password."
        } else {
            "a command marked `as root` is for a shell that is root already."
        }
    );
    if proposals.is_empty() {
        let _ = writeln!(out, "  nothing to propose");
    }
    for proposal in proposals {
        let _ = writeln!(out, "\n  {}: {}", safe(&proposal.id), safe(&proposal.title));
        let _ = writeln!(out, "    means     {}", safe(&proposal.means));
        let label = if proposal.needs_root && !prefixed {
            "as root"
        } else {
            "run"
        };
        for command in &proposal.commands {
            let words: Vec<String> = command.iter().map(|word| shell_quote(word)).collect();
            let _ = writeln!(out, "    {label:<9} {}", words.join(" "));
        }
        if let Some(how) = &proposal.by_hand {
            let _ = writeln!(out, "    by hand   {}", safe(how));
        }
    }
    let _ = writeln!(out, "\nNothing was changed.");
    out
}

/// One argument, quoted so a POSIX shell, bash, zsh, and fish all read it as
/// the same single word. The proposals carry printable ASCII without a
/// backslash, so single quotes, with `'` written `'\''`, are enough.
fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Machine-derived text, made safe for a terminal, flagged when anything was
/// removed or altered.
fn safe(text: &str) -> String {
    flagged(term_sanitize::display_str(text, LIMITS))
}

/// A path, from its bytes, the same way.
fn safe_path(path: &Path) -> String {
    flagged(term_sanitize::display_bytes(
        path.as_os_str().as_bytes(),
        LIMITS,
    ))
}

fn flagged(clean: term_sanitize::Clean) -> String {
    if clean.findings.is_empty() {
        return clean.text;
    }
    let what: Vec<String> = clean.findings.iter().map(ToString::to_string).collect();
    format!("{} [{}]", clean.text, what.join("; "))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::ffi::OsStr;
    use std::path::PathBuf;

    use xudo_backend::Probe;
    use xudo_backend::paths_to_root::{Answer, Caller, Lookup, MemoryHost};
    use xudo_policy::{Classification, Hint, HintSource};
    use xudo_sys::{Output, PrivilegedOps, Runner};

    use super::*;

    const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n\
        yamin:x:1000:1000::/home/yamin:/bin/sh\n\
        alice:x:1001:1001::/home/alice:/bin/sh\n";

    #[derive(Clone, Copy)]
    enum DriftRunnerMode {
        Normal,
        QueryError,
        QueryFailure,
        DigestError,
        DigestFailure,
        DigestEmpty,
        Obsolete,
        NewConffile,
    }

    struct DriftRunner(DriftRunnerMode);

    impl Runner for DriftRunner {
        fn run(
            &self,
            absolute_exe: &str,
            _args: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<Output, SysError> {
            if absolute_exe == "/usr/bin/dpkg-query" {
                if matches!(self.0, DriftRunnerMode::QueryError) {
                    return Err(SysError::unsupported("dpkg-query unavailable"));
                }
                return Ok(Output {
                    success: !matches!(self.0, DriftRunnerMode::QueryFailure),
                    code: Some(i32::from(matches!(self.0, DriftRunnerMode::QueryFailure))),
                    stdout: format!(
                        " /etc/xudo/rules.d/10-same.toml 00000000000000000000000000000000\n /etc/xudo/rules.d/20-changed.toml {}\n",
                        match self.0 {
                            DriftRunnerMode::Obsolete => {
                                "11111111111111111111111111111111 obsolete"
                            }
                            DriftRunnerMode::NewConffile => "newconffile",
                            _ => "11111111111111111111111111111111",
                        }
                    ),
                    stderr: String::new(),
                });
            }
            if matches!(self.0, DriftRunnerMode::DigestError) {
                return Err(SysError::unsupported("md5sum unavailable"));
            }
            if matches!(self.0, DriftRunnerMode::DigestFailure) {
                return Ok(Output {
                    success: false,
                    code: Some(1),
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            if matches!(self.0, DriftRunnerMode::DigestEmpty) {
                return Ok(Output {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            let digest = match stdin {
                Some(b"same") => "00000000000000000000000000000000",
                Some(b"changed") => "22222222222222222222222222222222",
                _ => return Err(SysError::unsupported("unexpected digest input")),
            };
            Ok(Output {
                success: true,
                code: Some(0),
                stdout: format!("{digest}  -\n"),
                stderr: String::new(),
            })
        }
    }

    fn summarize_sudoers(entries: Result<Vec<SudoersEntry>, String>) -> SnippetReport {
        summarize_sudoers_scan(entries, Path::new("/etc/sudoers.d/xudo"))
    }

    fn read_candidate_fixture(path: &Path) -> Result<Option<Vec<u8>>, String> {
        std::fs::read(path)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_locally_edited_shipped_rule_is_reported_as_changed_locally() {
        let root = Path::new("/etc/xudo/rules.d");
        let paths = [
            root.join("10-same.toml"),
            root.join("20-changed.toml"),
            root.join("30-own.toml"),
        ];
        let trusted = [
            TrustedFile {
                name: "10-same.toml".into(),
                bytes: b"same".to_vec(),
            },
            TrustedFile {
                name: "20-changed.toml".into(),
                bytes: b"changed".to_vec(),
            },
            TrustedFile {
                name: "30-own.toml".into(),
                bytes: b"mine".to_vec(),
            },
        ];
        let report = rule_drift_from_trusted(
            root,
            &paths,
            &trusted,
            &DriftRunner(DriftRunnerMode::Normal),
        );
        assert_eq!(report.files[0].status, RuleDriftStatus::MatchesShipped);
        assert_eq!(report.files[1].status, RuleDriftStatus::ChangedLocally);
        assert_eq!(report.files[2].status, RuleDriftStatus::NotFromPackage);
        assert_eq!(report.unavailable, None);
        let obsolete = rule_drift_from_trusted(
            root,
            &paths,
            &trusted,
            &DriftRunner(DriftRunnerMode::Obsolete),
        );
        assert_eq!(obsolete.files[1].status, RuleDriftStatus::NoLongerShipped);
    }

    #[test]
    fn rule_drift_accepts_test_supplied_trusted_files_on_every_platform() {
        let loaded = fixture_rules("direct-trusted");
        let path = loaded.files()[0].clone();
        let trusted = Ok(vec![TrustedFile {
            name: path.file_name().unwrap().to_os_string(),
            bytes: std::fs::read(&path).unwrap(),
        }]);

        let report = rule_drift(path.parent().unwrap(), Ok(&loaded), &trusted);

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, path.display().to_string());
        // The fixture is never a dpkg conffile, so it can never match a shipped rule.
        assert_ne!(report.files[0].status, RuleDriftStatus::MatchesShipped);
    }

    fn conffile_blob(lines: &[&str]) -> String {
        let mut blob = String::new();
        for line in lines {
            blob.push_str(line);
            blob.push('\n');
        }
        blob
    }

    #[test]
    fn an_obsolete_conffile_is_not_reported_as_shipped() {
        let md5 = "0123456789abcdef0123456789abcdef";
        let parsed = parse_conffiles(&conffile_blob(&[
            "",
            "   ",
            &format!(" not-absolute {md5}"),
            &format!(" /etc/xudo/good.toml {md5} obsolete"),
            &format!(" /etc/xudo/remove.toml {md5} remove-on-upgrade"),
            &format!(" /etc/xudo/both.toml {md5} obsolete remove-on-upgrade"),
            " /etc/xudo/short.toml abc",
            " /etc/xudo/nonhex.toml z123456789abcdef0123456789abcdef",
            " /etc/xudo/upper.toml 0123456789ABCDEF0123456789ABCDEF",
            " /etc/xudo/no-digest.toml",
            &format!("/etc/xudo/no-leading-space.toml {md5}"),
            "obsolete",
        ]));
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed
                .get(b"/etc/xudo/good.toml".as_slice())
                .map(|record| (record.status, record.digest.as_str())),
            Some((ConffileStatus::Obsolete, md5))
        );
        assert_eq!(
            parsed
                .get(b"/etc/xudo/remove.toml".as_slice())
                .map(|r| r.status),
            Some(ConffileStatus::Obsolete)
        );
        assert_eq!(
            parsed
                .get(b"/etc/xudo/both.toml".as_slice())
                .map(|record| (record.status, record.digest.as_str())),
            Some((ConffileStatus::Obsolete, md5))
        );
    }

    #[test]
    fn a_new_conffile_record_without_a_hash_is_unknown() {
        let parsed = parse_conffiles(&conffile_blob(&[
            " /etc/new.toml newconffile",
            " /etc/x/fresh.toml newconffile obsolete",
        ]));
        assert_eq!(
            parsed.get(b"/etc/new.toml".as_slice()).map(|r| r.status),
            Some(ConffileStatus::New)
        );
        assert_eq!(
            parsed
                .get(b"/etc/x/fresh.toml".as_slice())
                .map(|r| r.status),
            Some(ConffileStatus::New)
        );
        let root = Path::new("/etc/xudo/rules.d");
        let files = [root.join("20-changed.toml")];
        let report = rule_drift_from_trusted(
            root,
            &files,
            &[TrustedFile {
                name: "20-changed.toml".into(),
                bytes: b"new".to_vec(),
            }],
            &DriftRunner(DriftRunnerMode::NewConffile),
        );
        assert_eq!(report.files[0].status, RuleDriftStatus::Unknown);
        assert_eq!(
            report.unavailable.as_deref(),
            Some("dpkg reports a new conffile without a baseline")
        );
    }

    #[test]
    fn a_path_ending_in_a_flag_word_keeps_its_last_word() {
        let md5 = "0123456789abcdef0123456789abcdef";
        let parsed = parse_conffiles(&conffile_blob(&[
            &format!(" /etc/x/foo obsolete {md5}"),
            &format!(" /etc/x/foo remove-on-upgrade {md5}"),
            &format!(" /etc/x/bar obsolete {md5} obsolete"),
        ]));
        assert_eq!(
            parsed
                .get(b"/etc/x/foo obsolete".as_slice())
                .map(|record| (record.status, record.digest.as_str())),
            Some((ConffileStatus::Shipped, md5))
        );
        assert_eq!(
            parsed
                .get(b"/etc/x/foo remove-on-upgrade".as_slice())
                .map(|record| record.status),
            Some(ConffileStatus::Shipped)
        );
        assert_eq!(
            parsed
                .get(b"/etc/x/bar obsolete".as_slice())
                .map(|record| (record.status, record.digest.as_str())),
            Some((ConffileStatus::Obsolete, md5))
        );
        assert!(!parsed.contains_key(b"/etc/x/foo".as_slice()));
    }

    #[test]
    fn a_path_with_a_double_space_or_a_tab_is_not_collapsed() {
        let md5 = "0123456789abcdef0123456789abcdef";
        let parsed = parse_conffiles(&conffile_blob(&[
            &format!(" /etc/x/foo  bar.toml {md5}"),
            &format!(" /etc/x/foo\tbar.toml {md5}"),
        ]));
        assert_eq!(
            parsed
                .get(b"/etc/x/foo  bar.toml".as_slice())
                .map(|record| (record.status, record.digest.as_str())),
            Some((ConffileStatus::Shipped, md5))
        );
        assert_eq!(
            parsed
                .get(b"/etc/x/foo\tbar.toml".as_slice())
                .map(|record| record.status),
            Some(ConffileStatus::Shipped)
        );
        assert!(!parsed.contains_key(b"/etc/x/foo bar.toml".as_slice()));
    }

    #[test]
    fn a_missing_dpkg_record_is_unknown_instead_of_clean() {
        let root = Path::new("/etc/xudo/rules.d");
        let paths = [root.join("10-same.toml")];
        let report = rule_drift_from_trusted(
            root,
            &paths,
            &[TrustedFile {
                name: "10-same.toml".into(),
                bytes: b"same".to_vec(),
            }],
            &DriftRunner(DriftRunnerMode::QueryFailure),
        );
        assert_eq!(report.files[0].status, RuleDriftStatus::Unknown);
        assert!(report.unavailable.is_some());
    }

    #[test]
    fn a_failed_or_incomplete_drift_check_is_unknown() {
        let root = Path::new("/etc/xudo/rules.d");
        let path = [root.join("10-same.toml")];
        let trusted = [TrustedFile {
            name: "10-same.toml".into(),
            bytes: b"same".to_vec(),
        }];
        for mode in [
            DriftRunnerMode::QueryError,
            DriftRunnerMode::DigestError,
            DriftRunnerMode::DigestFailure,
            DriftRunnerMode::DigestEmpty,
        ] {
            let report = rule_drift_from_trusted(root, &path, &trusted, &DriftRunner(mode));
            assert_eq!(report.files[0].status, RuleDriftStatus::Unknown);
            assert!(report.unavailable.is_some());
        }
        let missing_name = [PathBuf::from("/")];
        let report = rule_drift_from_trusted(
            root,
            &missing_name,
            &trusted,
            &DriftRunner(DriftRunnerMode::Normal),
        );
        assert_eq!(report.files[0].status, RuleDriftStatus::Unknown);
        let missing_trusted =
            rule_drift_from_trusted(root, &path, &[], &DriftRunner(DriftRunnerMode::Normal));
        assert_eq!(missing_trusted.files[0].status, RuleDriftStatus::Unknown);
        let bad_digest = rule_drift_from_trusted(
            root,
            &path,
            &[TrustedFile {
                name: "10-same.toml".into(),
                bytes: b"unexpected".to_vec(),
            }],
            &DriftRunner(DriftRunnerMode::Normal),
        );
        assert_eq!(bad_digest.files[0].status, RuleDriftStatus::Unknown);
    }

    #[test]
    fn a_snippet_named_with_a_dot_is_reported_not_in_effect() {
        let marked = |name: &str| SudoersEntry::File {
            path: PathBuf::from("/etc/sudoers.d").join(name),
            bytes: Ok(Some(b"# Managed by xudo.\n".to_vec())),
        };
        let report = summarize_sudoers(Ok(vec![
            marked("xudo.conf"),
            marked("xudo~"),
            marked("xudo"),
        ]));
        assert_eq!(report.installed_rule, Some(true));
        assert_eq!(
            report.not_in_effect,
            ["/etc/sudoers.d/xudo.conf", "/etc/sudoers.d/xudo~"]
        );
        let dotted_only = summarize_sudoers(Ok(vec![marked("xudo.conf")]));
        assert_eq!(dotted_only.installed_rule, Some(false));
        assert!(snippet_name_is_ignored(b"xudo.conf"));
        assert!(snippet_name_is_ignored(b"xudo~"));
        assert!(!snippet_name_is_ignored(b"xudo"));
    }

    #[test]
    fn an_unreadable_sudoers_path_is_unknown() {
        let report = summarize_sudoers(Err("directory unreadable".to_owned()));
        assert_eq!(report.installed_rule, None);
        assert_eq!(report.unavailable.as_deref(), Some("directory unreadable"));
        let report = summarize_sudoers(Ok(vec![SudoersEntry::File {
            path: PathBuf::from("/etc/sudoers.d/xudo"),
            bytes: Err("not trusted".to_owned()),
        }]));
        assert_eq!(report.installed_rule, None);
        assert_eq!(report.unavailable.as_deref(), Some("not trusted"));
        let report = summarize_sudoers(Ok(vec![SudoersEntry::File {
            path: PathBuf::from("/etc/sudoers.d/unrelated"),
            bytes: Ok(None),
        }]));
        assert_eq!(report.installed_rule, Some(false));
        assert!(report.unavailable.is_none());
        let report = summarize_sudoers(Ok(vec![SudoersEntry::File {
            path: PathBuf::from("/etc/sudoers.d/xudo"),
            bytes: Ok(None),
        }]));
        assert_eq!(report.installed_rule, None);
        let report = summarize_sudoers(Ok(vec![SudoersEntry::Error("entry vanished".to_owned())]));
        assert_eq!(report.installed_rule, None);
        assert_eq!(report.unavailable.as_deref(), Some("entry vanished"));
    }

    #[test]
    fn sudoers_scan_reads_candidates_and_uses_only_the_canonical_name() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join("doctor-sudoers-scan");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xudo.conf"), b"# Managed by xudo.\n").unwrap();
        std::fs::write(dir.join("xudo"), b"# Managed by xudo.\n").unwrap();
        std::fs::write(dir.join("other.conf"), b"operator content\n").unwrap();
        let report = sudoers_snippets_at(&dir, &read_candidate_fixture);
        assert_eq!(report.installed_rule, Some(true));
        assert_eq!(
            report.not_in_effect,
            [dir.join("xudo.conf").display().to_string()]
        );
        assert!(report.unavailable.is_none());
        let absent = sudoers_snippets_at(&dir.join("absent"), &read_candidate_fixture);
        assert_eq!(absent.installed_rule, None);
        let unreadable = sudoers_snippets_at(&dir, &|_| Err("untrusted".to_owned()));
        assert_eq!(unreadable.installed_rule, None);
        assert!(unreadable.unavailable.is_some());
        assert!(matches!(
            map_sudoers_entry(
                Err(std::io::Error::other("entry vanished")),
                &read_candidate_fixture,
            ),
            SudoersEntry::Error(reason) if reason.contains("entry vanished")
        ));
        assert!(read_candidate_fixture(&dir.join("missing")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sudoers_candidates_use_the_trusted_file_reader() {
        let candidate = read_sudoers_candidate(Path::new("/usr/bin/true")).unwrap();
        assert!(candidate.is_some());
        assert!(read_sudoers_candidate(Path::new("/proc/self/environ")).is_err());
    }

    #[test]
    fn sudoers_candidate_reader_returns_the_injected_file_result() {
        let path = Path::new("/etc/sudoers.d/xudo");
        let expected = b"# Managed by xudo.\n".to_vec();
        let expected_path = path.to_owned();
        let fixture = expected.clone();
        let result = read_sudoers_candidate_with(path, &move |seen| {
            assert_eq!(seen, expected_path);
            Ok(Some(fixture.clone()))
        });
        assert_eq!(result.unwrap(), Some(expected));

        let rejected = read_sudoers_candidate_with(path, &|_| Err("untrusted".to_owned()));
        assert_eq!(rejected, Err("untrusted".to_owned()));
    }

    /// A platform that answers the same on every host.
    struct TestOps {
        release: &'static str,
        observable: bool,
    }

    impl PrivilegedOps for TestOps {
        fn platform(&self) -> &'static str {
            "test"
        }

        fn kernel(&self) -> KernelSupport {
            KernelSupport::parse(self.release)
        }

        fn classify(&self, _pid: u32) -> Result<CallerFacts, SysError> {
            if self.observable {
                Ok(CallerFacts::new(
                    Classification::Unattested {
                        reason: "no broker".to_owned(),
                    },
                    1000,
                )
                .with_hint(Hint::new(HintSource::Environment, "CLAUDECODE", "1")))
            } else {
                Err(SysError::read("self/stat", "test stub refuses"))
            }
        }

        fn resolve_exe(&self, _path: &str) -> Result<PathBuf, SysError> {
            Err(SysError::unsupported("resolve_exe"))
        }
    }

    /// A backend that is present at the given paths, with the given banner,
    /// honouring everything but, optionally, the per-command scope.
    struct TestProbe {
        present: &'static [&'static str],
        banner: Option<&'static str>,
        scoped: bool,
    }

    impl Probe for TestProbe {
        fn exists(&self, absolute_path: &str) -> bool {
            self.present.contains(&absolute_path)
        }
        fn version_banner(&self, _absolute_path: &str) -> Option<String> {
            self.banner.map(ToOwned::to_owned)
        }
        fn directory_exists(&self, _absolute_path: &str) -> bool {
            true
        }
        fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            true
        }
        fn honours_scoped_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            self.scoped
        }
        fn validates_named_file(&self, _absolute_path: &str) -> bool {
            true
        }
        fn accepts_argument_wildcard(&self, _absolute_path: &str) -> bool {
            true
        }
    }

    const SUDO: TestProbe = TestProbe {
        present: &["/usr/bin/sudo"],
        banner: Some("Sudo version 1.9.17p2"),
        scoped: true,
    };

    fn gathered(
        host: &MemoryHost,
        path: &str,
        ops: &TestOps,
        probe: &TestProbe,
        loaded: Result<&LoadedRules, &LoadError>,
        fix: bool,
    ) -> Report {
        let platform = Platform {
            ops,
            probe,
            host,
            path: Some(OsStr::new(path)),
        };
        let mut report = gather(Path::new("/usr/bin"), loaded, &platform, fix);
        // Pinned rather than walked: the walk judges the mounts under the
        // path, and where it can judge them at all (not on macOS, which has
        // no mount table) the answer belongs to the machine the suite is on.
        report.ruleset.trust = TrustReport {
            trusted: true,
            files_checked: Some(0),
            reason: None,
        };
        report.ruleset.package_drift = match loaded {
            Ok(loaded) => RuleDriftReport {
                files: loaded
                    .files()
                    .iter()
                    .enumerate()
                    .map(|(index, _)| RuleDriftRow {
                        path: format!("/usr/bin/rule-{index}.toml"),
                        status: RuleDriftStatus::Unknown,
                    })
                    .collect(),
                unavailable: Some("test fixture has no dpkg record".to_owned()),
            },
            Err(_) => RuleDriftReport {
                files: Vec::new(),
                unavailable: Some("rules did not load".to_owned()),
            },
        };
        report.sudoers_snippet = SnippetReport {
            installed_rule: None,
            not_in_effect: Vec::new(),
            ignored_reason: "sudo skips filenames containing a dot or ending in ~",
            unavailable: Some("test fixture has no sudoers directory".to_owned()),
        };
        report
    }

    /// One rule file, in a directory of the caller's own: the tests run in
    /// parallel, and two sharing a directory delete each other's.
    fn fixture_rules(name: &str) -> LoadedRules {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("doctor-rules-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("10-rules.toml"),
            "[[action]]\nid = \"xudo.svc.restart\"\ntier = \"svc-control\"\n\
             exe = \"/usr/bin/systemctl\"\nargs = [\n  { name = \"verb\", matcher = { literal = \
             \"restart\" } },\n]\n",
        )
        .unwrap();
        LoadedRules::from_dir(&dir).unwrap()
    }

    /// Nothing wrong, everything readable, and the caller already in `xudo`.
    fn clean_host() -> MemoryHost {
        MemoryHost::new(Caller {
            uid: 1000,
            gid: 1000,
            groups: Lookup::Found(vec![1000, 998]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"xudo:x:998:yamin\nyamin:x:1000:\n",
        )
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"Defaults secure_path=\"/usr/sbin:/usr/bin\"\n#includedir /etc/sudoers.d\n",
        )
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/usr/bin/sudo", 0, 0, 0o4755, b"")
        .dir("/usr/sbin", 0, 0, 0o755)
        .dir("/root", 0, 0, 0o700)
        .dir("/home", 0, 0, 0o755)
        .dir("/home/yamin", 1000, 1000, 0o755)
    }

    /// One of nearly every way to root another way, and things it cannot see.
    fn hostile_host() -> MemoryHost {
        MemoryHost::new(Caller {
            uid: 1000,
            gid: 1000,
            groups: Lookup::Found(vec![1000, 999, 996, 4, 4242]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"adm:x:4:yamin\ndocker:x:999:yamin\nlxd:x:997:yamin\nlibvirt:x:996:\n\
              xudo:x:998:\nyamin:x:1000:\n",
        )
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"Defaults secure_path=\"/usr/sbin:/usr/bin:/opt/rootbin\"\n\
              #includedir /etc/sudoers.d\n\
              %adm ALL=(ALL) NOPASSWD: /usr/bin/apt\n\
              @include \"/etc/sudoers.l\\\nocal\"\n",
        )
        .dir("/etc/sudoers.d", 0, 0, 0o750)
        .file(
            "/etc/sudoers.d/90 cloud",
            0,
            0,
            0o440,
            b"alice ALL=(ALL) NOPASSWD:ALL\n",
        )
        .file(
            "/etc/sudoers.d/91-defaults",
            0,
            0,
            0o440,
            b"Defaults:ADMINS !authenticate\n",
        )
        .unreadable_file("/etc/sudoers.d/99-secret", 0, 0, 0o440)
        .file("/etc/doas.conf", 0, 0, 0o400, b"permit nopass :wheel\n")
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, 4, 0o775)
        .dir("/run", 0, 0, 0o755)
        .dir("/run/systemd", 0, 0, 0o755)
        .dir("/run/systemd/system", 1001, 1001, 0o755)
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/lib", 0, 0, 0o755)
        .dir("/usr/lib/systemd", 0, 0, 0o1777)
        .dir("/usr/lib/systemd/system", 0, 0, 0o755)
        .file("/usr/lib/systemd/system/b.service", 4242, 4243, 0o664, b"")
        .dir("/usr/local", 0, 0, 0o755)
        .dir("/usr/local/lib", 0, 0, 0o755)
        .dir("/usr/local/lib/systemd", 0, 0, 0o755)
        .dir("/usr/local/lib/systemd/system", 0, 0, 0o755)
        .acl_writable("/usr/local/lib/systemd/system")
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .file("/usr/bin/gpasswd", 0, 0, 0o755, b"")
        .dir("/usr/sbin", 0, 0, 0o755)
        .file("/usr/sbin/usermod", 0, 0, 0o755, b"")
        .file("/usr/sbin/visudo", 0, 0, 0o755, b"")
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/rootbin", 1000, 1000, 0o755)
        .file("/etc/environment", 0, 0, 0o666, b"")
        .dir("/etc/profile.d", 0, 0, 0o755)
        .file("/etc/profile.d/x\x1b[2Jy.sh", 0, 0, 0o666, b"")
        .sealed_dir("/root", 0, 0, 0o700)
        .dir("/srv", 0, 0, 0o755)
        .sealed_dir("/srv/sealed", 0, 0, 0o700)
        .dir("/home", 0, 0, 0o755)
        .dir("/home/yamin", 1000, 1000, 0o755)
        .dir("/home/yamin/bin", 1000, 1000, 0o755)
    }

    fn hostile_report(fix: bool) -> Report {
        let missing = LoadError::Directory {
            dir: "/etc/xudo/rules.d".to_owned(),
            reason: "No such file or directory (os error 2)".to_owned(),
        };
        let mut report = gathered(
            &hostile_host(),
            "/home/yamin/bin::/srv/sealed/a/b:/usr/bin",
            &TestOps {
                release: "5.10.0-21-amd64",
                observable: false,
            },
            &TestProbe {
                present: &["/usr/bin/sudo"],
                banner: Some("sudo-rs 0.2.2"),
                scoped: false,
            },
            Err(&missing),
            fix,
        );
        // Pinned rather than walked, so the snapshot names no checkout.
        report.ruleset.dir = "/etc/xudo/rules.d".to_owned();
        report.ruleset.trust = TrustReport {
            trusted: false,
            files_checked: None,
            reason: Some("/etc/xudo is owned by uid 1000, not root".to_owned()),
        };
        report
    }

    #[test]
    fn the_lifecycle_note_sits_between_the_ruleset_and_trust_rows() {
        let mut out = "ruleset      1 action(s)\nrules trust  ok\n".to_owned();
        insert_ruleset_notes(&mut out, Some("note line"), &[]);
        assert_eq!(
            out,
            "ruleset      1 action(s)\nnote line\nrules trust  ok\n"
        );
        let mut untouched = out.clone();
        insert_ruleset_notes(&mut untouched, None, &[]);
        assert_eq!(untouched, out);
        let mut no_anchor = "ruleset only\n".to_owned();
        insert_ruleset_notes(&mut no_anchor, Some("note line"), &[]);
        assert_eq!(no_anchor, "ruleset only\n");
        let lint = OpenUnitLintRow {
            action: "xudo.svc.lifecycle".to_owned(),
            file: "20-services.toml".to_owned(),
            line: 4,
            message: "xudo.svc.lifecycle at 20-services.toml:4: this rule can start or stop any unit: replace the unit matcher with a one-of list of your units".to_owned(),
        };
        let mut with_lint = "ruleset      1 action(s)\nrules trust  ok\n".to_owned();
        insert_ruleset_notes(&mut with_lint, None, std::slice::from_ref(&lint));
        assert!(
            with_lint.contains("this rule can start or stop any unit: replace the unit matcher with a one-of list of your units"),
            "{with_lint}"
        );
        assert!(with_lint.contains("\nrules trust"), "{with_lint}");
        let mut both = "ruleset      1 action(s)\nrules trust  ok\n".to_owned();
        insert_ruleset_notes(&mut both, Some("note line"), std::slice::from_ref(&lint));
        assert!(both.contains("note line\n"), "{both}");
        assert!(
            both.find("note line").unwrap() < both.find("one-of list").unwrap(),
            "{both}"
        );
        let mut lint_no_anchor = "ruleset only\n".to_owned();
        insert_ruleset_notes(&mut lint_no_anchor, None, std::slice::from_ref(&lint));
        assert_eq!(lint_no_anchor, "ruleset only\n");
    }

    #[test]
    fn doctor_reports_an_open_unit_matcher() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join("doctor-open-unit");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("20-services.toml"),
            "[[action]]\nid = \"xudo.svc.lifecycle\"\ntier = \"svc-control\"\n\
             exe = \"/usr/bin/systemctl\"\nargs = [\n  { name = \"verb\", matcher = { literal = \
             \"restart\" } },\n  { name = \"unit\", matcher = { name = \"unit-name\" } },\n]\n",
        )
        .unwrap();
        let loaded = LoadedRules::from_dir(&dir).unwrap();
        let section = ruleset(&dir, Ok(&loaded));
        assert!(section.lifecycle_note.is_none());
        let found = section.open_unit_lints.first().unwrap();
        assert_eq!(found.action, "xudo.svc.lifecycle");
        assert_eq!(found.file, "20-services.toml");
        assert!(
            found.message.contains(
                "this rule can start or stop any unit: replace the unit matcher with a one-of list of your units"
            ),
            "{}",
            found.message
        );
        let report = gathered(
            &clean_host(),
            "/usr/bin",
            &TestOps {
                release: "6.8.0-90-generic",
                observable: true,
            },
            &SUDO,
            Ok(&loaded),
            false,
        );
        let text = human(&report);
        assert!(
            text.contains(
                "this rule can start or stop any unit: replace the unit matcher with a one-of list of your units"
            ),
            "{text}"
        );
        let json = render::json_of(&report);
        assert!(json.contains("\"open_unit_lints\""), "{json}");
        assert!(json.contains("xudo.svc.lifecycle"), "{json}");
    }

    #[test]
    fn the_envelope_of_a_clean_machine_is_pinned() {
        let loaded = fixture_rules("1");
        let report = gathered(
            &clean_host(),
            "/usr/bin:/home/yamin/bin",
            &TestOps {
                release: "6.8.0-90-generic",
                observable: true,
            },
            &SUDO,
            Ok(&loaded),
            false,
        );
        insta::assert_snapshot!("json_clean", render::json_of(&report));
        let fixed = gathered(
            &clean_host(),
            "/usr/bin:/home/yamin/bin",
            &TestOps {
                release: "6.8.0-90-generic",
                observable: true,
            },
            &SUDO,
            Ok(&loaded),
            true,
        );
        insta::assert_snapshot!("human_clean_fix", human(&fixed));
    }

    #[test]
    fn the_envelope_of_a_machine_with_every_other_path_to_root_is_pinned() {
        let hostile = hostile_report(true);
        assert!(
            hostile.ruleset.lifecycle_note.is_none(),
            "a ruleset that did not load has no lifecycle note"
        );
        assert!(
            !human(&hostile).contains("no service lifecycle rule:"),
            "an unloaded ruleset must not ask for a lifecycle file"
        );
        insta::assert_snapshot!("json_every_path", render::json_of(&hostile_report(true)));
        insta::assert_snapshot!("human_every_path", human(&hostile_report(true)));
    }

    #[test]
    fn package_drift_and_ignored_snippets_are_pinned_in_both_renderers() {
        let mut report = hostile_report(false);
        report.ruleset.package_drift = RuleDriftReport {
            files: vec![
                RuleDriftRow {
                    path: "/etc/xudo/rules.d/00-shipped.toml".to_owned(),
                    status: RuleDriftStatus::MatchesShipped,
                },
                RuleDriftRow {
                    path: "/etc/xudo/rules.d/05-edited.toml".to_owned(),
                    status: RuleDriftStatus::ChangedLocally,
                },
                RuleDriftRow {
                    path: "/etc/xudo/rules.d/06-obsolete.toml".to_owned(),
                    status: RuleDriftStatus::NoLongerShipped,
                },
                RuleDriftRow {
                    path: "/etc/xudo/rules.d/99-operator.toml".to_owned(),
                    status: RuleDriftStatus::NotFromPackage,
                },
                RuleDriftRow {
                    path: "/etc/xudo/rules.d/90-unknown.toml".to_owned(),
                    status: RuleDriftStatus::Unknown,
                },
            ],
            unavailable: Some("dpkg-query unavailable".to_owned()),
        };
        report.sudoers_snippet = SnippetReport {
            installed_rule: Some(false),
            not_in_effect: vec!["/etc/sudoers.d/xudo.conf".to_owned()],
            ignored_reason: "sudo skips filenames containing a dot or ending in ~",
            unavailable: Some("one candidate was not trusted".to_owned()),
        };
        insta::assert_snapshot!("human_package_drift", human(&report));
        insta::assert_snapshot!("json_package_drift", render::json_of(&report));
        report.sudoers_snippet.installed_rule = Some(true);
        report.ruleset.package_drift.unavailable = None;
        report.sudoers_snippet.unavailable = None;
        insta::assert_snapshot!("human_installed_snippet", human(&report));
    }

    #[test]
    fn root_with_no_backend_is_told_to_run_commands_as_root() {
        let host = MemoryHost::new(Caller {
            uid: 0,
            gid: 0,
            groups: Lookup::Found(vec![0]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file("/etc/group", 0, 0, 0o644, b"root:x:0:\n")
        .dir("/etc/profile.d", 0, 0, 0o755)
        .file("/etc/profile.d/evil.sh", 0, 0, 0o666, b"")
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .dir("/root", 0, 0, 0o700);
        let report = gathered(
            &host,
            "/usr/bin",
            &TestOps {
                release: "6.13.0",
                observable: true,
            },
            &TestProbe {
                present: &[],
                banner: None,
                scoped: true,
            },
            Ok(&fixture_rules("2")),
            true,
        );
        insta::assert_snapshot!("human_root_no_backend", human(&report));
        assert_eq!(report.backend.status, BackendStatus::None);
        assert!(report.paths_to_root.subject.is_root);
    }

    #[test]
    fn root_is_shown_what_sudo_itself_says_about_the_xudo_group() {
        let host = MemoryHost::new(Caller {
            uid: 0,
            gid: 0,
            groups: Lookup::Found(vec![0]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file("/etc/group", 0, 0, 0o644, b"root:x:0:\nxudo:x:998:alice\n")
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .dir("/root", 0, 0, 0o700)
        .sudo_says(
            "alice",
            Answer::Passwordless("(ALL) NOPASSWD: ALL".to_owned()),
        );
        let report = gathered(
            &host,
            "/usr/bin",
            &TestOps {
                release: "6.13.0",
                observable: true,
            },
            &TestProbe {
                present: &["/usr/bin/sudo"],
                banner: Some("Sudo version 1.9.16"),
                scoped: true,
            },
            Ok(&fixture_rules("4")),
            false,
        );
        insta::assert_snapshot!("human_root_sudo_says", human(&report));
    }

    #[test]
    fn a_doas_nopass_answer_is_shown_for_the_user_who_ran_the_doctor() {
        let host = MemoryHost::new(Caller {
            uid: 1000,
            gid: 1000,
            groups: Lookup::Found(vec![1000]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file("/etc/group", 0, 0, 0o644, b"root:x:0:\n")
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/etc/doas.conf", 0, 0, 0o644, b"")
        .doas_says(
            "/etc/doas.conf",
            "/bin/sh",
            Answer::Passwordless("permit nopass".to_owned()),
        );
        let report = gathered(
            &host,
            "/usr/bin",
            &TestOps {
                release: "6.13.0",
                observable: true,
            },
            &TestProbe {
                present: &["/usr/bin/doas"],
                banner: None,
                scoped: true,
            },
            Ok(&fixture_rules("4")),
            false,
        );
        let text = human(&report);
        assert!(
            text.contains(
                "doas itself permits /bin/sh for you without a password, by /etc/doas.conf"
            )
        );
        assert!(text.contains("does not apply to the doas backend"));
        assert!(!text.contains("sudoers xudo unknown:"));
    }

    #[test]
    fn denies_a_backend_banner_or_reason_that_would_rewrite_the_terminal() {
        // The version banner is whatever the backend prints, the refusal and
        // the unavailability reason name whatever the machine says, and the
        // kernel line is a release string: none is trusted for a terminal.
        let attack = "x\u{1b}[2J\u{9b}31m\u{202e}y\u{7f}";
        let mut report = hostile_report(false);
        report.backend.refusal = Some(attack.to_owned());
        report.caller.unavailable = Some(attack.to_owned());
        report.kernel.summary = attack.to_owned();
        let text = human(&report);
        for bad in ['\u{1b}', '\u{9b}', '\u{202e}', '\u{7f}'] {
            assert!(!text.contains(bad), "{bad:?} in {text}");
        }
        assert!(text.contains("UNUSABLE: x"), "{text}");
        report.backend.status = BackendStatus::Usable;
        report.backend.version = Some(attack.to_owned());
        let text = human(&report);
        for bad in ['\u{1b}', '\u{9b}', '\u{202e}', '\u{7f}'] {
            assert!(!text.contains(bad), "{bad:?} in {text}");
        }
        // The envelope is ASCII, so a terminal shown it raw is safe too, and
        // it still parses to the same strings.
        let json = render::json_of(&report);
        assert!(
            json.bytes()
                .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte)),
            "{json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["backend"]["version"], attack);
    }

    #[test]
    fn names_a_caller_with_no_passwd_entry_by_uid_on_every_platform() {
        // The real host decides whether the running user has a name, so a test
        // that only meets the real host reaches this arm on a machine where
        // the user is nameless and not on one where they are not.
        let mut report = hostile_report(false);
        report.paths_to_root.subject.name = None;
        let text = human(&report);
        assert!(text.contains("other paths to root, as uid 1000:"), "{text}");
        assert!(!text.contains("yamin (uid"), "{text}");
    }

    #[test]
    fn a_backend_with_no_banner_says_so_rather_than_inventing_one() {
        let report = gathered(
            &clean_host(),
            "/usr/bin",
            &TestOps {
                release: "6.8.0",
                observable: true,
            },
            &TestProbe {
                present: &["/usr/bin/sudo"],
                banner: None,
                scoped: true,
            },
            Ok(&fixture_rules("3")),
            false,
        );
        let text = human(&report);
        assert!(
            text.contains("backend      sudo-rs (no version banner)"),
            "{text}"
        );
        assert_eq!(report.backend.version.as_deref(), Some(""));
    }

    #[test]
    fn run_writes_prose_or_the_envelope_and_always_reports_success() {
        let host = clean_host();
        let loaded = fixture_rules("4");
        let platform = Platform {
            ops: &TestOps {
                release: "6.8.0",
                observable: true,
            },
            probe: &SUDO,
            host: &host,
            path: None,
        };
        let mut prose = Vec::new();
        let code = run(
            Path::new("/usr/bin"),
            Ok(&loaded),
            &platform,
            false,
            false,
            &mut prose,
        );
        assert_eq!(code, ExitCode::Delegated);
        assert!(String::from_utf8_lossy(&prose).starts_with("platform     test\n"));
        let mut envelope = Vec::new();
        let code = run(
            Path::new("/usr/bin"),
            Ok(&loaded),
            &platform,
            true,
            false,
            &mut envelope,
        );
        assert_eq!(code, ExitCode::Delegated);
        let parsed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(parsed["schema_version"], DOCTOR_SCHEMA_VERSION);
        // No PATH was handed over, so that check says it could not look.
        assert_eq!(parsed["paths_to_root"]["checks"][4]["status"], "unverified");
        // The real walk: a root-owned path with a mount root made is trusted
        // on Linux, and nothing is trusted where there is no mount table.
        #[cfg(target_os = "linux")]
        assert_eq!(parsed["ruleset"]["trust"]["files_checked"], 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(parsed["ruleset"]["trust"]["trusted"], false);
        assert!(
            TestOps {
                release: "6.8",
                observable: true
            }
            .resolve_exe("/bin/true")
            .is_err()
        );
    }

    #[test]
    fn denies_a_file_name_that_would_rewrite_the_terminal() {
        // Anyone can name a file in a world-writable directory. Its name is
        // shown with the escape removed and a flag that something was.
        let text = human(&hostile_report(false));
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(
            text.contains("/etc/profile.d/xy.sh [1 terminal escape sequence(s) removed]"),
            "{text}"
        );
        // A path that is not UTF-8 is shown as such, from its bytes.
        let odd = Path::new(OsStr::from_bytes(b"/etc/\xff"));
        assert_eq!(
            safe_path(odd),
            "/etc/\u{fffd} [invalid UTF-8 replaced with \u{fffd}]"
        );
        assert_eq!(safe("plain"), "plain");
    }

    #[test]
    fn denies_a_printed_command_that_a_shell_would_split_or_expand() {
        assert_eq!(shell_quote("/usr/sbin/visudo"), "/usr/sbin/visudo");
        assert_eq!(shell_quote("go-w"), "go-w");
        assert_eq!(
            shell_quote("/etc/sudoers.d/90 cloud"),
            "'/etc/sudoers.d/90 cloud'"
        );
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("*"), "'*'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn every_backend_status_and_trust_answer_has_its_wire_name() {
        let names: Vec<serde_json::Value> = [
            BackendStatus::Usable,
            BackendStatus::Unusable,
            BackendStatus::None,
        ]
        .iter()
        .map(|status| serde_json::to_value(status).unwrap())
        .collect();
        assert_eq!(names, ["usable", "unusable", "none"]);
        let report = hostile_report(false);
        assert_eq!(report.backend.status, BackendStatus::Unusable);
        assert_eq!(report.proposals, None);
        assert_eq!(
            report.backend.missing_required,
            vec![Capability::PerCommandDefaults]
        );
        assert!(!report.kernel.agent_path_available);
        assert!(report.kernel.withheld_because.is_some());
        assert_eq!(report.caller.classification, None);
        assert!(report.caller.password_required);
    }
}
