//! The root-written harness registry, as data.
//!
//! A harness is a name root chose, not a fact about a binary. This module
//! parses one registry file and answers whether a live session record still
//! names that exact entry. It does not read the filesystem, and nothing here
//! grants a passwordless run yet.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Separates an entry hash from every other SHA-256 the project computes.
const ENTRY_DOMAIN: &[u8] = b"xudo.harness.entry.v1\0";

/// The most reviewers, or session users, one entry may name.
const MAX_NAMES: usize = 32;

/// The most concurrent sessions one entry may declare.
const MAX_SESSIONS: u32 = 1024;

/// How a harness is started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HarnessWay {
    /// A long-running service under its own account (`User=`).
    Service,
    /// A session a listed person may start, under that person's uid.
    Session,
}

impl HarnessWay {
    /// The word a record and a rule file use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Session => "session",
        }
    }
}

/// One registry entry, after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HarnessEntry {
    /// The label root chose. `[a-z0-9-]{1,32}`.
    pub label: String,
    /// Service or session.
    pub way: HarnessWay,
    /// The service account, when [`HarnessWay::Service`].
    pub account: Option<String>,
    /// Who may start a session, when [`HarnessWay::Session`].
    pub users: Vec<String>,
    /// Who may see this harness's ask-human entries.
    pub reviewers: Vec<String>,
    /// How many live sessions root allows. Stored and hashed; not enforced yet.
    pub max_sessions: u32,
    hash: [u8; 32],
}

impl HarnessEntry {
    /// The entry hash as 64 lowercase hex characters.
    ///
    /// A session record carries this. A registry edit changes it, and a record
    /// that still names the old digest is no longer this harness.
    pub fn hash_hex(&self) -> String {
        use std::fmt::Write as _;

        self.hash
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                // Writing into a String cannot fail.
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// Whether `uid` is the service account or one of the session users.
    ///
    /// `resolve` maps an account name to a uid. A name it cannot resolve does
    /// not match: a missing account withholds the harness.
    pub fn uid_matches(&self, uid: u32, resolve: &dyn Fn(&str) -> Option<u32>) -> bool {
        match self.way {
            HarnessWay::Service => self
                .account
                .as_deref()
                .is_some_and(|name| resolve(name) == Some(uid)),
            HarnessWay::Session => self.users.iter().any(|name| resolve(name) == Some(uid)),
        }
    }

    /// Canonical bytes of the fields that define the entry. Not the file bytes:
    /// comments and spacing are not policy.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, self.label.as_bytes());
        put(&mut out, self.way.as_str().as_bytes());
        put(&mut out, self.account.as_deref().unwrap_or("").as_bytes());
        put_len(&mut out, self.users.len());
        for user in &self.users {
            put(&mut out, user.as_bytes());
        }
        put_len(&mut out, self.reviewers.len());
        for reviewer in &self.reviewers {
            put(&mut out, reviewer.as_bytes());
        }
        out.extend_from_slice(&self.max_sessions.to_be_bytes());
        out
    }
}

/// Every harness root has registered, keyed by label.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HarnessRegistry {
    entries: BTreeMap<String, HarnessEntry>,
}

impl HarnessRegistry {
    /// No harnesses. A peer is never a harness against this.
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Whether any entry is loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry named `label`, if root still registers it.
    pub fn get(&self, label: &str) -> Option<&HarnessEntry> {
        self.entries.get(label)
    }

    /// Entries in label order. The ruleset generation walks this order.
    pub fn entries(&self) -> impl Iterator<Item = &HarnessEntry> {
        self.entries.values()
    }

    /// Whether a live record still names this registry and this uid.
    ///
    /// The label must be present, the way and the entry hash must be the
    /// current entry's, and the uid must be the account or a listed user.
    pub fn attests(
        &self,
        label: &str,
        way: HarnessWay,
        entry_hash: &str,
        uid: u32,
        resolve: &dyn Fn(&str) -> Option<u32>,
    ) -> bool {
        let Some(entry) = self.get(label) else {
            return false;
        };
        entry.way == way && entry.hash_hex() == entry_hash && entry.uid_matches(uid, resolve)
    }

    /// Builds a registry from named file texts.
    ///
    /// `name` is the file name (`codex.toml`). The stem must equal the label
    /// inside the file. Two files may not share a label.
    ///
    /// # Errors
    ///
    /// Returns the first file that is not a registry file.
    pub fn from_files<I, N, T>(files: I) -> Result<Self, HarnessError>
    where
        I: IntoIterator<Item = (N, T)>,
        N: AsRef<str>,
        T: AsRef<str>,
    {
        let files = files
            .into_iter()
            .map(|(name, text)| (name.as_ref().to_owned(), text.as_ref().to_owned()))
            .collect();
        Self::from_named_files(files)
    }

    fn from_named_files(files: Vec<(String, String)>) -> Result<Self, HarnessError> {
        let mut entries = BTreeMap::new();
        for (name, text) in files {
            let entry = parse_harness_file(&name, &text)?;
            insert_harness_entry(&mut entries, &name, entry)?;
        }
        refuse_reviewer_overlap(&entries)?;
        Ok(Self { entries })
    }
}

/// A reviewer decides what a harness's agents queue, so no reviewer may be a
/// harness account or user, of this entry or of any other: an agent that could
/// act as its own reviewer would approve itself.
fn refuse_reviewer_overlap(entries: &BTreeMap<String, HarnessEntry>) -> Result<(), HarnessError> {
    let agents: BTreeSet<&str> = entries
        .values()
        .flat_map(|entry| entry.account.iter().chain(entry.users.iter()))
        .map(String::as_str)
        .collect();
    for entry in entries.values() {
        if let Some(reviewer) = entry
            .reviewers
            .iter()
            .find(|reviewer| agents.contains(reviewer.as_str()))
        {
            return Err(HarnessError::ReviewerIsHarnessAccount {
                label: entry.label.clone(),
                reviewer: reviewer.clone(),
            });
        }
    }
    Ok(())
}

fn insert_harness_entry(
    entries: &mut BTreeMap<String, HarnessEntry>,
    file: &str,
    entry: HarnessEntry,
) -> Result<(), HarnessError> {
    let label = entry.label.clone();
    if entries.insert(label.clone(), entry).is_some() {
        return Err(HarnessError::DuplicateLabel {
            label,
            file: file.to_owned(),
        });
    }
    Ok(())
}

/// Why a registry file was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HarnessError {
    /// The file name is not `<label>.toml`.
    #[error("{file} is not a harness file name: a harness file is named <label>.toml")]
    NotAHarnessFile {
        /// The file name.
        file: String,
    },
    /// The text is not TOML, or it contains a key this file does not have.
    #[error("harness file {file}: {reason}")]
    Parse {
        /// The file.
        file: String,
        /// The parser's account of why.
        reason: String,
    },
    /// A field does not meet the registry rules.
    #[error("harness file {file}: {reason}")]
    Invalid {
        /// The file.
        file: String,
        /// What was wrong.
        reason: String,
    },
    /// Two files register the same label.
    #[error("harness label {label} is registered twice (again in {file})")]
    DuplicateLabel {
        /// The label.
        label: String,
        /// The second file.
        file: String,
    },
    /// A reviewer is also the account or a user of some harness.
    #[error(
        "harness {label}: reviewer {reviewer} is a harness account or user; reviewers must be disjoint from every harness's account and users"
    )]
    ReviewerIsHarnessAccount {
        /// The harness that lists the reviewer.
        label: String,
        /// The reviewer.
        reviewer: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct HarnessFile {
    label: String,
    way: HarnessWay,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    users: Option<Vec<String>>,
    reviewers: Vec<String>,
    max_sessions: u32,
}

/// Whether `label` is `[a-z][a-z0-9-]{0,31}`.
pub fn valid_harness_label(label: &str) -> bool {
    let mut bytes = label.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    label.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Whether `name` is an account name: `[a-z_][a-z0-9_-]{0,31}`.
pub fn valid_account_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() || first == b'_' => {}
        _ => return false,
    }
    name.len() <= 32
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

/// Parses one harness file. `name` is the file name, and its stem must be the label.
///
/// # Errors
///
/// Returns [`HarnessError`] when the name, the text, or a field is refused.
pub fn parse_harness_file(name: &str, text: &str) -> Result<HarnessEntry, HarnessError> {
    let Some(stem) = harness_stem(name) else {
        return Err(HarnessError::NotAHarnessFile {
            file: name.to_owned(),
        });
    };
    let parsed: HarnessFile = toml::from_str(text).map_err(|error| HarnessError::Parse {
        file: name.to_owned(),
        reason: error.to_string(),
    })?;
    let entry = validate_harness(name, stem, parsed)?;
    Ok(entry)
}

fn harness_stem(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".toml")?;
    (!stem.is_empty() && !stem.contains('/') && !stem.contains('\\')).then_some(stem)
}

fn validate_harness(
    file: &str,
    stem: &str,
    parsed: HarnessFile,
) -> Result<HarnessEntry, HarnessError> {
    let invalid = |reason: String| HarnessError::Invalid {
        file: file.to_owned(),
        reason,
    };
    if !valid_harness_label(&parsed.label) {
        return Err(invalid(format!(
            "label {:?} is not [a-z0-9-]{{1,32}}",
            parsed.label
        )));
    }
    if parsed.label != stem {
        return Err(invalid(format!(
            "label {:?} does not match the file name {stem}.toml",
            parsed.label
        )));
    }
    if parsed.max_sessions == 0 || parsed.max_sessions > MAX_SESSIONS {
        return Err(invalid(format!(
            "max-sessions must be 1..={MAX_SESSIONS}, got {}",
            parsed.max_sessions
        )));
    }
    validate_names(file, "reviewers", &parsed.reviewers, 1)?;
    let (account, users) = match parsed.way {
        HarnessWay::Service => {
            if parsed.users.is_some() {
                return Err(invalid(
                    "a service harness names account, not users".to_owned(),
                ));
            }
            let Some(account) = parsed.account else {
                return Err(invalid(
                    "a service harness must name its account".to_owned(),
                ));
            };
            if !valid_account_name(&account) {
                return Err(invalid(format!(
                    "account {account:?} is not an account name"
                )));
            }
            (Some(account), Vec::new())
        }
        HarnessWay::Session => {
            if parsed.account.is_some() {
                return Err(invalid(
                    "a session harness names users, not account".to_owned(),
                ));
            }
            let Some(users) = parsed.users else {
                return Err(invalid("a session harness must name its users".to_owned()));
            };
            validate_names(file, "users", &users, 1)?;
            (None, users)
        }
    };
    let reviewers = parsed.reviewers;
    let mut entry = HarnessEntry {
        label: parsed.label,
        way: parsed.way,
        account,
        users,
        reviewers,
        max_sessions: parsed.max_sessions,
        hash: [0; 32],
    };
    entry.hash = entry_hash(&entry.canonical());
    Ok(entry)
}

fn validate_names(
    file: &str,
    field: &str,
    names: &[String],
    min: usize,
) -> Result<(), HarnessError> {
    if names.len() < min || names.len() > MAX_NAMES {
        return Err(HarnessError::Invalid {
            file: file.to_owned(),
            reason: format!(
                "{field} must name {min}..={MAX_NAMES} accounts, got {}",
                names.len()
            ),
        });
    }
    let mut seen = BTreeSet::<&str>::new();
    for name in names {
        if !valid_account_name(name) {
            return Err(HarnessError::Invalid {
                file: file.to_owned(),
                reason: format!("{field} entry {name:?} is not an account name"),
            });
        }
        if !seen.insert(name.as_str()) {
            return Err(HarnessError::Invalid {
                file: file.to_owned(),
                reason: format!("{field} lists {name:?} twice"),
            });
        }
    }
    Ok(())
}

fn entry_hash(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hasher.update(canonical);
    hasher.finalize().into()
}

/// The uid of `name` in a `/etc/passwd` text, if the line is well formed.
///
/// The first matching name wins. A comment, a short line, and a `+` inclusion
/// are not a match. This does not read the file.
pub fn passwd_uid(text: &str, name: &str) -> Option<u32> {
    if !valid_account_name(name) {
        return None;
    }
    let prefix = format!("{name}:");
    let line = text
        .lines()
        .find(|line| !line.starts_with('#') && line.starts_with(&prefix))?;
    line.split(':').nth(2)?.parse().ok()
}

/// [`passwd_uid`] over bytes already read. Invalid UTF-8 and a failed read
/// are both "no such account".
pub fn uid_from_passwd_read<E>(read: Result<Vec<u8>, E>, name: &str) -> Option<u32> {
    let bytes = read.ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    passwd_uid(text, name)
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    put_len(out, field.len());
    out.extend_from_slice(field);
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn test_account_uid(name: &str) -> Option<u32> {
        (name == "agent").then_some(1000)
    }

    const SERVICE: &str = r#"
label = "codex"
way = "service"
account = "agent"
reviewers = ["alice"]
max-sessions = 4
"#;

    const SESSION: &str = r#"
label = "claude"
way = "session"
users = ["alice", "bob"]
reviewers = ["carol"]
max-sessions = 1
"#;

    fn overlap_error(files: &[(&str, &str)]) -> HarnessError {
        HarnessRegistry::from_files(files.iter().copied()).unwrap_err()
    }

    #[test]
    fn a_reviewer_that_is_a_harness_account_fails_to_load() {
        let text = SERVICE.replace(r#"["alice"]"#, r#"["alice", "agent"]"#);
        let error = overlap_error(&[("codex.toml", &text)]);
        assert_eq!(
            error,
            HarnessError::ReviewerIsHarnessAccount {
                label: "codex".to_owned(),
                reviewer: "agent".to_owned(),
            }
        );
        assert!(error.to_string().contains("disjoint"));
    }

    #[test]
    fn a_reviewer_that_is_a_harness_user_fails_to_load() {
        let text = SESSION.replace(r#"["carol"]"#, r#"["bob"]"#);
        let error = overlap_error(&[("claude.toml", &text)]);
        assert_eq!(
            error,
            HarnessError::ReviewerIsHarnessAccount {
                label: "claude".to_owned(),
                reviewer: "bob".to_owned(),
            }
        );
    }

    #[test]
    fn a_reviewer_overlapping_another_harness_fails_to_load() {
        // alice reviews codex but is a user of claude.
        let error = overlap_error(&[("codex.toml", SERVICE), ("claude.toml", SESSION)]);
        assert_eq!(
            error,
            HarnessError::ReviewerIsHarnessAccount {
                label: "codex".to_owned(),
                reviewer: "alice".to_owned(),
            }
        );
        let other = SESSION.replace(r#"["carol"]"#, r#"["agent"]"#);
        let error = overlap_error(&[("codex.toml", SERVICE), ("claude.toml", &other)]);
        assert!(matches!(
            error,
            HarnessError::ReviewerIsHarnessAccount { ref reviewer, .. } if reviewer == "agent"
        ));
    }

    #[test]
    fn disjoint_reviewers_load_across_harnesses() {
        let service = SERVICE.replace(r#"["alice"]"#, r#"["carol"]"#);
        let registry = HarnessRegistry::from_files([
            ("codex.toml", service.as_str()),
            ("claude.toml", SESSION),
        ])
        .unwrap();
        assert_eq!(registry.entries().count(), 2);
    }

    fn service() -> HarnessEntry {
        parse_harness_file("codex.toml", SERVICE).unwrap()
    }

    #[test]
    fn a_service_file_parses_and_its_hash_is_stable() {
        let entry = service();
        assert_eq!(entry.way, HarnessWay::Service);
        assert_eq!(entry.account.as_deref(), Some("agent"));
        assert!(entry.users.is_empty());
        assert_eq!(entry.hash_hex().len(), 64);
        assert_eq!(entry.hash_hex(), service().hash_hex());
        assert!(
            entry
                .hash_hex()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(entry.way.as_str(), "service");
        assert_eq!(HarnessWay::Session.as_str(), "session");
    }

    #[test]
    fn a_session_file_parses_and_matches_only_its_users() {
        let entry = parse_harness_file("claude.toml", SESSION).unwrap();
        let resolve = |name: &str| match name {
            "alice" => Some(1000),
            "bob" => Some(1001),
            _ => None,
        };
        assert!(entry.uid_matches(1000, &resolve));
        assert!(entry.uid_matches(1001, &resolve));
        assert!(!entry.uid_matches(1002, &resolve));
        assert!(!service().uid_matches(1000, &resolve));
        assert!(service().uid_matches(7, &|name| (name == "agent").then_some(7)));
        assert!(!service().uid_matches(7, &|_| None));
    }

    #[test]
    fn changing_any_field_changes_the_entry_hash() {
        let base = service();
        let changed = [
            SERVICE.replace("codex", "codey"),
            SERVICE.replace("agent", "runner"),
            SERVICE.replace("[\"alice\"]", "[\"bob\"]"),
            SERVICE.replace("max-sessions = 4", "max-sessions = 5"),
        ];
        let names = ["codey.toml", "codex.toml", "codex.toml", "codex.toml"];
        for (text, name) in changed.iter().zip(names) {
            let entry = parse_harness_file(name, text).unwrap();
            assert_ne!(entry.hash_hex(), base.hash_hex(), "{name}");
            assert_ne!(entry.canonical(), base.canonical(), "{name}");
        }
    }

    #[test]
    fn a_file_that_names_both_ways_or_neither_is_refused() {
        let both = SERVICE.replace(
            "account = \"agent\"\n",
            "account = \"agent\"\nusers = [\"alice\"]\n",
        );
        assert!(parse_harness_file("codex.toml", &both).is_err());
        let neither = SERVICE.replace("account = \"agent\"\n", "");
        assert!(parse_harness_file("codex.toml", &neither).is_err());
        let session_account =
            SESSION.replace("users = [\"alice\", \"bob\"]\n", "account = \"alice\"\n");
        assert!(parse_harness_file("claude.toml", &session_account).is_err());
        let session_without = SESSION.replace("users = [\"alice\", \"bob\"]\n", "");
        assert!(parse_harness_file("claude.toml", &session_without).is_err());
    }

    #[test]
    fn bad_labels_names_bounds_and_unknown_keys_are_refused() {
        assert!(parse_harness_file("Codex.toml", SERVICE).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("codex", "Codex")).is_err());
        assert!(
            parse_harness_file("codex.toml", &SERVICE.replace("codex", "no_underscore")).is_err()
        );
        assert!(parse_harness_file(".toml", SERVICE).is_err());
        assert!(parse_harness_file("codex", SERVICE).is_err());
        assert!(parse_harness_file("a/codex.toml", SERVICE).is_err());
        let long = "a".repeat(33);
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("codex", &long)).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("agent", "Agent")).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("alice", "bad name")).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("agent", "a.b")).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace('4', "0")).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace('4', "1025")).is_err());
        assert!(parse_harness_file("codex.toml", &SERVICE.replace("[\"alice\"]", "[]")).is_err());
        assert!(
            parse_harness_file(
                "codex.toml",
                &SERVICE.replace("[\"alice\"]", "[\"alice\", \"alice\"]")
            )
            .is_err()
        );
        let too_many = format!(
            "[{}]",
            (0..33)
                .map(|n| format!("\"u{n}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(
            parse_harness_file("codex.toml", &SERVICE.replace("[\"alice\"]", &too_many)).is_err()
        );
        assert!(parse_harness_file("codex.toml", &format!("{SERVICE}extra = true\n")).is_err());
        assert!(parse_harness_file("other.toml", SERVICE).is_err());
        assert!(
            HarnessRegistry::from_files([("codex.toml", "not = valid registry data")]).is_err()
        );
        assert!(
            HarnessRegistry::from_files([(
                "claude.toml",
                &SESSION.replace("[\"alice\", \"bob\"]", "[\"bad name\"]")
            )])
            .is_err()
        );
        assert!(!valid_harness_label(""));
        assert!(!valid_harness_label("A"));
        assert!(valid_harness_label("a"));
        assert!(valid_harness_label("a-1"));
        assert!(!valid_harness_label(&"a".repeat(33)));
        assert!(!valid_account_name(""));
        assert!(!valid_account_name("1abc"));
        assert!(valid_account_name("_x"));
        let service = SERVICE.replace("[\"alice\"]", "[\"carol\"]");
        let ok = HarnessRegistry::from_files([
            ("codex.toml", service.as_str()),
            ("claude.toml", SESSION),
        ])
        .unwrap();
        assert!(ok.get("codex").is_some());
        assert_eq!(ok.entries().count(), 2);
        assert!(HarnessRegistry::empty().is_empty());
        assert!(!ok.is_empty());
    }

    #[test]
    fn a_harness_label_cannot_start_with_a_digit_or_dash() {
        for label in ["1codex", "-codex", "1", "-"] {
            assert!(!valid_harness_label(label), "{label}");
            let text = SERVICE.replace("\"codex\"", &format!("\"{label}\""));
            assert!(parse_harness_file(&format!("{label}.toml"), &text).is_err());
        }
    }

    #[test]
    fn registry_rejects_duplicate_labels() {
        let result =
            HarnessRegistry::from_files([("codex.toml", SERVICE), ("codex.toml", SERVICE)]);
        assert!(result.is_err());
    }

    #[test]
    fn attests_requires_the_current_entry_and_the_uid() {
        let registry = HarnessRegistry::from_files([("codex.toml", SERVICE)]).unwrap();
        let entry = registry.get("codex").unwrap();
        let resolve = test_account_uid;
        assert!(registry.attests(
            "codex",
            HarnessWay::Service,
            &entry.hash_hex(),
            1000,
            &resolve
        ));
        assert!(!registry.attests(
            "missing",
            HarnessWay::Service,
            &entry.hash_hex(),
            1000,
            &resolve
        ));
        assert!(!registry.attests(
            "codex",
            HarnessWay::Session,
            &entry.hash_hex(),
            1000,
            &resolve
        ));
        assert!(!registry.attests(
            "codex",
            HarnessWay::Service,
            &"ab".repeat(32),
            1000,
            &resolve
        ));
        assert!(!registry.attests(
            "codex",
            HarnessWay::Service,
            &entry.hash_hex(),
            1001,
            &resolve
        ));
        assert!(!HarnessRegistry::empty().attests(
            "codex",
            HarnessWay::Service,
            &entry.hash_hex(),
            1000,
            &resolve
        ));
    }

    #[test]
    fn an_unregistered_same_uid_process_is_not_a_harness() {
        let registry = HarnessRegistry::from_files([("codex.toml", SERVICE)]).unwrap();
        let entry = registry.get("codex").unwrap();
        let resolve = test_account_uid;
        assert!(entry.uid_matches(1000, &resolve));
        assert_eq!(test_account_uid("unregistered"), None);
        assert!(!registry.attests(
            "unregistered",
            HarnessWay::Service,
            &entry.hash_hex(),
            1000,
            &resolve
        ));
    }

    #[test]
    fn a_record_whose_label_left_the_registry_is_not_a_harness() {
        let registered = HarnessRegistry::from_files([("codex.toml", SERVICE)]).unwrap();
        let entry = registered.get("codex").unwrap();
        let empty = HarnessRegistry::empty();
        assert!(!empty.attests(
            "codex",
            HarnessWay::Service,
            &entry.hash_hex(),
            1000,
            &|_| None
        ));
    }

    #[test]
    fn a_changed_registry_entry_voids_its_records() {
        let old = HarnessRegistry::from_files([("codex.toml", SERVICE)]).unwrap();
        let new_text = SERVICE.replace("max-sessions = 4", "max-sessions = 5");
        let current = HarnessRegistry::from_files([("codex.toml", new_text)]).unwrap();
        let old_hash = old.get("codex").unwrap().hash_hex();
        assert!(!current.attests("codex", HarnessWay::Service, &old_hash, 1000, &|_| None));
    }

    #[test]
    fn passwd_text_resolves_only_a_well_formed_matching_line() {
        let text = "# comment\n\nroot:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000:agent:/:/bin/sh\nbad:x:nope:1\nshort\n+agent::::::\n";
        assert_eq!(passwd_uid(text, "root"), Some(0));
        assert_eq!(passwd_uid(text, "agent"), Some(1000));
        assert_eq!(passwd_uid(text, "bad"), None);
        assert_eq!(passwd_uid(text, "missing"), None);
        assert_eq!(passwd_uid(text, "Nope"), None);
        assert_eq!(passwd_uid(text, "+agent"), None);
        let bytes = text.as_bytes().to_vec();
        assert_eq!(
            uid_from_passwd_read(Ok::<_, ()>(bytes), "agent"),
            Some(1000)
        );
        assert_eq!(
            uid_from_passwd_read(Ok::<_, ()>(vec![0xff, 0xfe]), "agent"),
            None
        );
        assert_eq!(uid_from_passwd_read(Err::<Vec<u8>, _>(()), "agent"), None);
        assert_eq!(
            uid_from_passwd_read(Ok::<_, ()>(b"agent:x\n".to_vec()), "agent"),
            None
        );
        assert_eq!(
            uid_from_passwd_read(Ok::<_, ()>(b"agent\n".to_vec()), "agent"),
            None
        );
    }
}
