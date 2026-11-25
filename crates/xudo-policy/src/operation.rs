//! Typed operations. A rule here names work xudo itself performs.
//!
//! `remove-path` deletes a path under a fixed tree. The rule is the tree, the
//! limits, and which owners may be removed. The target is one relative path
//! under that tree. This module decides whether the request fits a rule. It
//! does not open, resolve, or unlink anything: that walk lives in `xudo-sys`,
//! and a decision here is not authority to touch the filesystem.
//!
//! A `harness` list is parsed and checked against the registry, the same way
//! an action's list is. It is not a grant. This step is the password path
//! only. A later step may arm the label; until then every caller, including a
//! listed harness, authenticates.

use crate::caller::CallerFacts;
use crate::decision::{Confirm, Decision, DenialCode, ENVELOPE_SCHEMA_VERSION, TraceStep, Verdict};
use crate::deny::{contains_protected_path, touches_protected_path};
use crate::engine::Settings;
use crate::harness::{passwd_uid, valid_account_name, valid_harness_label};
use crate::rule::{ActionId, RuleSet, Source};

/// Longest absolute path an operation rule or a target may name.
pub const MAX_PATH_BYTES: usize = 4096;

/// Longest single component.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Deepest relative path a rule may allow, counted from `under`.
pub const MAX_DEPTH_LIMIT: u32 = 32;

/// Most entries one operation may remove.
pub const MAX_ENTRIES_LIMIT: u32 = 100_000;

/// Which built-in an `[[operation]]` rule runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpKind {
    /// Remove a path under `under`. Never `/bin/rm`.
    RemovePath,
}

impl OpKind {
    /// The word a rule file and the wire use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemovePath => "remove-path",
        }
    }
}

/// Whose entries the walk may remove.
///
/// Omitted owners mean any uid except root. A listed name is resolved from the
/// passwd text the broker already read. An unknown name fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerPolicy {
    /// Every uid except 0. Root-owned entries are kept.
    AnyButRoot,
    /// Only these uids. The list is the resolved rule, in declaration order.
    Only(Vec<u32>),
}

/// One validated `[[operation]]` rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Operation {
    /// Stable id, unique across actions, deny rules, and operations.
    pub id: ActionId,
    /// Which built-in.
    pub op: OpKind,
    /// Absolute tree root. The walk never removes this directory itself.
    pub under: String,
    /// Whether a directory target is removed with its contents.
    pub recursive: bool,
    /// Deepest relative path, counted in components from `under`.
    pub max_depth: u32,
    /// Most entries one request may remove.
    pub max_entries: u32,
    /// Account names whose entries may be removed.
    ///
    /// Absent means any owner except root. An empty list is a load error:
    /// it would remove nothing and look like a rule.
    #[serde(default)]
    pub owners: Option<Vec<String>>,
    /// Harness labels. Parsed and checked against the registry. Not a grant
    /// on this step: the password path is the only way the operation runs.
    #[serde(default)]
    pub harness: Vec<String>,
    /// Assigned by the loader. A rule file cannot set it.
    #[serde(skip)]
    pub source: Source,
}

/// What the walk is allowed to do once the password path has re-decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveGrant {
    /// The operation id, for the audit record.
    pub id: ActionId,
    /// Where the rule is defined.
    pub source: Source,
    /// Absolute tree, as bytes.
    pub under: Vec<u8>,
    /// Path relative to `under`, with no leading slash.
    pub relative: Vec<u8>,
    /// Whether a directory target may be removed.
    pub recursive: bool,
    /// Component cap, counted from `under`.
    pub max_depth: u32,
    /// Entry cap.
    pub max_entries: u32,
    /// Resolved owners.
    pub owners: OwnerPolicy,
}

const TREES: &[&[u8]] = &[
    b"/etc",
    b"/usr",
    b"/boot",
    b"/proc",
    b"/sys",
    b"/dev",
    b"/run",
    b"/root",
    b"/opt",
    b"/var/mail",
    b"/var/spool",
    b"/var/cache",
    b"/bin",
    b"/sbin",
    b"/lib",
    b"/lib32",
    b"/lib64",
    b"/libx32",
];

/// Why `under` cannot be a tree root. `None` means the lexical check passed.
pub fn forbidden_under(under: &[u8]) -> Option<&'static str> {
    if under == b"/" {
        return Some("the filesystem root");
    }
    if under == b"/home" {
        return Some("/home itself");
    }
    for tree in TREES {
        if under == *tree
            || under
                .strip_prefix(*tree)
                .is_some_and(|rest| rest.starts_with(b"/"))
        {
            return Some("a protected system directory");
        }
    }
    if touches_protected_path(under) {
        return Some("an xudo protected prefix");
    }
    if contains_protected_path(under) {
        return Some("an ancestor of an xudo protected prefix");
    }
    None
}

/// Load-time check for one operation. The caller turns the string into a
/// [`crate::rule::RuleSetError`].
///
/// # Errors
///
/// Returns the reason the request or rule is refused.
pub fn check_operation(op: &Operation) -> Result<(), String> {
    if op.id.as_str().is_empty()
        || op.id.as_str().len() > 128
        || !op.id.as_str().bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
        })
    {
        return Err("id must be 1..=128 bytes of [A-Za-z0-9._-]".to_owned());
    }
    clean_absolute(op.under.as_bytes())?;
    if let Some(why) = forbidden_under(op.under.as_bytes()) {
        return Err(format!("under {} is {why}", op.under.escape_debug()));
    }
    if op.max_depth == 0 || op.max_depth > MAX_DEPTH_LIMIT {
        return Err(format!("max-depth must be 1..={MAX_DEPTH_LIMIT}"));
    }
    if op.max_entries == 0 || op.max_entries > MAX_ENTRIES_LIMIT {
        return Err(format!("max-entries must be 1..={MAX_ENTRIES_LIMIT}"));
    }
    match &op.owners {
        None => {}
        Some(names) if names.is_empty() => {
            return Err("owners is empty; omit the key to allow any owner except root".to_owned());
        }
        Some(names) => {
            let mut seen = std::collections::BTreeSet::new();
            for name in names {
                if !valid_account_name(name) {
                    return Err(format!("owner {name:?} is not an account name"));
                }
                if name == "root" {
                    return Err("owners may not include uid 0 (root)".to_owned());
                }
                if !seen.insert(name.as_str()) {
                    return Err(format!("owner {name:?} is listed twice"));
                }
            }
        }
    }
    let mut seen_labels = std::collections::BTreeSet::new();
    for label in &op.harness {
        if !valid_harness_label(label) {
            return Err(format!("harness label {label:?} is not [a-z0-9-]{{1,32}}"));
        }
        if !seen_labels.insert(label.as_str()) {
            return Err(format!("harness label {label:?} is listed twice"));
        }
    }
    Ok(())
}

/// The relative path of `target` under `under`, or why it is not one.
///
/// `under` and `target` are absolute and lexically clean. A path that merely
/// shares a string prefix (`/srv/app/build` versus `/srv/app/build-evil`) is
/// refused. The tree root itself is refused. Component count is measured from
/// `under` and must be within `max_depth`.
///
/// # Errors
///
/// Returns the reason the request or rule is refused.
pub fn target_under(under: &[u8], target: &[u8], max_depth: u32) -> Result<Vec<u8>, &'static str> {
    clean_absolute(target).map_err(|_| "target is not a clean absolute path")?;
    if target == under {
        return Err("the tree root is never removed");
    }
    let relative = target
        .strip_prefix(under)
        .and_then(|rest| rest.strip_prefix(b"/"))
        .ok_or("target is outside the tree")?;
    check_relative(relative, max_depth)?;
    Ok(relative.to_vec())
}

/// The relative path under an already-accepted tree.
///
/// `clean_absolute` refuses these shapes in a full target. This still checks
/// them, and the unit test calls it directly so the arms stay reachable.
fn check_relative(relative: &[u8], max_depth: u32) -> Result<(), &'static str> {
    if relative.is_empty() {
        return Err("the tree root is never removed");
    }
    let mut depth = 0u32;
    for component in relative.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err("target has an empty, current, or parent component");
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err("target component is too long");
        }
        depth = depth.saturating_add(1);
    }
    if depth > max_depth {
        return Err("target is deeper than max-depth");
    }
    Ok(())
}

/// Resolves owner names. An omitted list is [`OwnerPolicy::AnyButRoot`].
///
/// # Errors
///
/// Returns the reason the request or rule is refused.
pub fn resolve_owners(op: &Operation, passwd: &str) -> Result<OwnerPolicy, String> {
    let Some(names) = &op.owners else {
        return Ok(OwnerPolicy::AnyButRoot);
    };
    let mut ids = Vec::with_capacity(names.len());
    for name in names {
        match passwd_uid(passwd, name) {
            Some(0) => return Err("owners may not include uid 0 (root)".to_owned()),
            Some(uid) => ids.push(uid),
            None => return Err(format!("owner {name} is not in passwd")),
        }
    }
    Ok(OwnerPolicy::Only(ids))
}

/// The operation that covers `target`, and the relative path under it.
///
/// The longest `under` that is a path-boundary prefix wins. A target equal to
/// any operation's `under` is the tree root and is refused, even when a
/// shorter tree would otherwise contain it.
///
/// # Errors
///
/// Returns the reason the request or rule is refused.
pub fn select<'a>(
    operations: &'a [Operation],
    target: &[u8],
) -> Result<(&'a Operation, Vec<u8>), &'static str> {
    clean_absolute(target).map_err(|_| "target is not a clean absolute path")?;
    if operations.iter().any(|op| op.under.as_bytes() == target) {
        return Err("the tree root is never removed");
    }
    let op = operations
        .iter()
        .filter(|op| {
            target
                .strip_prefix(op.under.as_bytes())
                .is_some_and(|rest| rest.starts_with(b"/"))
        })
        .max_by_key(|op| op.under.len())
        .ok_or("no remove-path rule covers this target")?;
    let relative = target_under(op.under.as_bytes(), target, op.max_depth)?;
    Ok((op, relative))
}

/// The grant the walk runs, or a denial. Frozen enrolled agents are refused
/// before a rule is consulted. A harness label is never consulted.
///
/// # Errors
///
/// Returns the reason the request or rule is refused.
pub fn judge_remove_path(
    rules: &RuleSet,
    caller: &CallerFacts,
    target: &[u8],
    settings: Settings,
    passwd: &str,
) -> Result<RemoveGrant, Box<Decision>> {
    if settings.frozen && caller.classification.is_enrolled_agent() {
        return Err(Box::new(Decision::deny(
            DenialCode::Frozen,
            display_target(target),
            Vec::new(),
        )));
    }
    let (op, relative) = match select(rules.operations(), target) {
        Ok(found) => found,
        Err(reason) => return Err(Box::new(refused(target, None, reason))),
    };
    let owners = match resolve_owners(op, passwd) {
        Ok(owners) => owners,
        Err(reason) => return Err(Box::new(refused(target, Some(op), &reason))),
    };
    Ok(RemoveGrant {
        id: op.id.clone(),
        source: op.source.clone(),
        under: op.under.as_bytes().to_vec(),
        relative,
        recursive: op.recursive,
        max_depth: op.max_depth,
        max_entries: op.max_entries,
        owners,
    })
}

/// The decision envelope for a remove-path request.
///
/// An allow means the password path may run the operation. It is not a
/// passwordless grant, and the `harness` list does not change it.
pub fn evaluate_remove_path(
    rules: &RuleSet,
    caller: &CallerFacts,
    target: &[u8],
    settings: Settings,
    passwd: &str,
) -> Decision {
    match judge_remove_path(rules, caller, target, settings, passwd) {
        Ok(grant) => Decision {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            verdict: Verdict::Allow,
            denial: None,
            remediation: None,
            action: Some(grant.id.clone()),
            rule_source: Some(grant.source.clone()),
            resolved_exe: None,
            resolved_argv: display_target(target),
            confirm: Confirm::NotRequired,
            harness_grant: None,
            trace: vec![
                TraceStep::OperationMatched {
                    action: grant.id.to_string(),
                    source: grant.source.to_string(),
                },
                TraceStep::ConfirmationDecided {
                    required: false,
                    reason: "a remove-path operation runs on the password path; harness labels are not a grant".to_owned(),
                },
            ],
        },
        Err(decision) => *decision,
    }
}

fn refused(target: &[u8], op: Option<&Operation>, reason: &str) -> Decision {
    let reason = reason.to_owned();
    let mut decision = Decision::deny(
        DenialCode::OperationRefused,
        display_target(target),
        vec![TraceStep::ActionRejected {
            action: op.map_or_else(|| "remove-path".to_owned(), |op| op.id.to_string()),
            reason: reason.clone(),
        }],
    );
    if let Some(op) = op {
        decision.action = Some(op.id.clone());
        decision.rule_source = Some(op.source.clone());
    }
    decision
}

fn display_target(target: &[u8]) -> Vec<String> {
    vec![target.escape_ascii().to_string()]
}

fn clean_absolute(path: &[u8]) -> Result<(), String> {
    if path.is_empty() || !path.starts_with(b"/") {
        return Err("path is not absolute".to_owned());
    }
    if path.len() > MAX_PATH_BYTES {
        return Err("path is longer than 4096 bytes".to_owned());
    }
    if path.contains(&0) {
        return Err("path contains NUL".to_owned());
    }
    for component in path.split(|byte| *byte == b'/').skip(1) {
        if component.is_empty() || component == b"." || component == b".." {
            return Err("path has an empty, current, or parent component".to_owned());
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err("path component is longer than 255 bytes".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::caller::Classification;
    use crate::rule::RuleSet;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000:agent:/home/agent:/bin/sh\nwww-data:x:33:33:www:/var/www:/usr/sbin/nologin\n";

    fn rules(text: &str) -> RuleSet {
        RuleSet::from_toml("50-remove-path.toml", text).unwrap()
    }

    fn sample() -> RuleSet {
        rules(
            r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 10000
owners = ["agent", "www-data"]
harness = ["codex"]
"#,
        )
    }

    fn operation(id: &str, under: &str, max_depth: u32) -> Operation {
        Operation {
            id: ActionId::new(id),
            op: OpKind::RemovePath,
            under: under.to_owned(),
            recursive: true,
            max_depth,
            max_entries: 100,
            owners: None,
            harness: Vec::new(),
            source: Source::default(),
        }
    }

    fn human() -> CallerFacts {
        CallerFacts::new(Classification::Human, 1000)
    }

    fn agent() -> CallerFacts {
        CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "codex".to_owned(),
                session_id: "s".to_owned(),
                declared_yolo: false,
            },
            1000,
        )
    }

    #[test]
    fn the_tree_root_is_never_removed() {
        let set = sample();
        let decision = evaluate_remove_path(
            &set,
            &human(),
            b"/srv/app/build",
            Settings::default(),
            PASSWD,
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.denial, Some(DenialCode::OperationRefused));
        assert_eq!(decision.denial.unwrap().as_u32(), 14);
        assert_eq!(decision.denial.unwrap().as_str(), "operation_refused");
        assert!(decision.remediation.unwrap().contains("do not retry"));
        assert!(
            judge_remove_path(
                &set,
                &human(),
                b"/srv/app/build",
                Settings::default(),
                PASSWD
            )
            .is_err()
        );
    }

    #[test]
    fn an_under_on_a_system_binary_or_spool_tree_is_refused() {
        for under in [
            "/bin",
            "/bin/sh",
            "/sbin",
            "/lib",
            "/lib32",
            "/lib64/ld",
            "/libx32",
            "/var/spool",
            "/var/spool/cron",
            "/var/cache",
            "/var/cache/apt",
        ] {
            assert!(forbidden_under(under.as_bytes()).is_some(), "{under}");
        }
        assert!(forbidden_under(b"/var/cachefoo").is_none());
        assert!(forbidden_under(b"/binx/tree").is_none());
    }

    #[test]
    fn a_tree_under_proc_or_xudo_state_fails_to_load() {
        let proc = RuleSet::from_toml(
            "bad.toml",
            r#"
[[operation]]
id = "bad.proc"
op = "remove-path"
under = "/proc/self"
recursive = false
max-depth = 1
max-entries = 1
"#,
        );
        let message = proc.unwrap_err().to_string();
        assert!(message.contains("/proc/self"), "{message}");
        assert!(message.contains("protected system directory"), "{message}");

        let state = RuleSet::from_toml(
            "bad.toml",
            r#"
[[operation]]
id = "bad.state"
op = "remove-path"
under = "/var/lib/xudo/spool"
recursive = false
max-depth = 1
max-entries = 1
"#,
        );
        let message = state.unwrap_err().to_string();
        assert!(message.contains("/var/lib/xudo/spool"), "{message}");
        assert!(message.contains("xudo protected prefix"), "{message}");

        for under in [
            "/",
            "/etc",
            "/etc/passwd",
            "/usr",
            "/usr/bin",
            "/boot",
            "/home",
            "/sys",
            "/dev",
            "/run",
            "/run/xudo",
            "/etc/xudo",
            "/var/spool",
            "/var/cache/apt",
        ] {
            let text = format!(
                "[[operation]]\nid = \"bad.tree\"\nop = \"remove-path\"\nunder = \"{under}\"\nrecursive = false\nmax-depth = 1\nmax-entries = 1\n"
            );
            assert!(RuleSet::from_toml("bad.toml", &text).is_err(), "{under}");
        }
        assert!(
            RuleSet::from_toml(
                "ok.toml",
                r#"
[[operation]]
id = "ok.home-child"
op = "remove-path"
under = "/home/alice/build"
recursive = false
max-depth = 2
max-entries = 4
"#,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_harness_label_does_not_change_the_verdict() {
        let with = sample();
        let without = rules(
            r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 10000
owners = ["agent", "www-data"]
"#,
        );
        let target = b"/srv/app/build/cache";
        let allowed = evaluate_remove_path(&with, &human(), target, Settings::default(), PASSWD);
        let also = evaluate_remove_path(&without, &human(), target, Settings::default(), PASSWD);
        assert_eq!(allowed.verdict, Verdict::Allow);
        assert_eq!(also.verdict, Verdict::Allow);
        assert_eq!(allowed.confirm, Confirm::NotRequired);
        assert_eq!(also.action, allowed.action);
        let frozen = evaluate_remove_path(
            &with,
            &agent(),
            target,
            Settings {
                frozen: true,
                ..Settings::default()
            },
            PASSWD,
        );
        assert_eq!(frozen.denial, Some(DenialCode::Frozen));
        let enrolled = evaluate_remove_path(&with, &agent(), target, Settings::default(), PASSWD);
        assert_eq!(enrolled.verdict, Verdict::Allow);
    }

    #[test]
    fn the_longest_under_wins_and_a_shared_prefix_does_not() {
        let operations = [
            operation("wide", "/srv/app", 8),
            operation("narrow", "/srv/app/build", 8),
        ];
        let (grant, relative) = select(&operations, b"/srv/app/build/cache").unwrap();
        assert_eq!(grant.id.as_str(), "narrow");
        assert_eq!(relative, b"cache");
        // `/srv/app/build-evil` shares a string prefix with `narrow` and is
        // still inside `wide`. The narrow rule must not claim it.
        let (shared, _) = select(&operations, b"/srv/app/build-evil/cache").unwrap();
        assert_eq!(shared.id.as_str(), "wide");
        let only_narrow = rules(
            r#"
[[operation]]
id = "narrow"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 10
"#,
        );
        let outside = evaluate_remove_path(
            &only_narrow,
            &human(),
            b"/srv/app/build-evil/cache",
            Settings::default(),
            "",
        );
        assert_eq!(outside.denial, Some(DenialCode::OperationRefused));
        assert_eq!(
            target_under(b"/srv/app/build", b"/srv/app/build-evil", 8).unwrap_err(),
            "target is outside the tree"
        );
    }

    #[test]
    fn target_under_refuses_each_shape_itself() {
        for (target, why) in [
            (&b"rel"[..], "target is not a clean absolute path"),
            (b"/srv/a/../x", "target is not a clean absolute path"),
            (b"/srv/a", "the tree root is never removed"),
            (b"/srv/b/x", "target is outside the tree"),
            (b"/srv/ab/x", "target is outside the tree"),
            (b"/srv/a/x/y", "target is deeper than max-depth"),
        ] {
            assert_eq!(target_under(b"/srv/a", target, 1).unwrap_err(), why);
        }
        assert_eq!(target_under(b"/srv/a", b"/srv/a/x", 1).unwrap(), b"x");
    }

    #[test]
    fn the_longest_under_wins_whatever_order_the_rules_are_listed_in() {
        let operations = [
            operation("narrow", "/srv/app/build", 8),
            operation("wide", "/srv/app", 8),
        ];
        assert_eq!(
            select(&operations, b"/srv/app/build/cache")
                .unwrap()
                .0
                .id
                .as_str(),
            "narrow"
        );
    }

    #[test]
    fn owners_resolve_or_fail_closed_and_empty_owners_do_not_load() {
        let set = sample();
        let grant = judge_remove_path(
            &set,
            &human(),
            b"/srv/app/build/cache",
            Settings::default(),
            PASSWD,
        )
        .unwrap();
        assert_eq!(grant.owners, OwnerPolicy::Only(vec![1000, 33]));
        let missing = evaluate_remove_path(
            &set,
            &human(),
            b"/srv/app/build/cache",
            Settings::default(),
            "root:x:0:0:root:/root:/bin/sh\n",
        );
        assert_eq!(missing.denial, Some(DenialCode::OperationRefused));
        assert!(
            RuleSet::from_toml(
                "bad.toml",
                r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 10
owners = []
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn dotdot_trailing_slash_and_depth_are_refused() {
        let set = sample();
        for target in [
            &b"/srv/app/build/../etc"[..],
            &b"/srv/app/build/cache/"[..],
            &b"/srv/app/build//cache"[..],
            &b"/srv/app/build/./cache"[..],
            &b"srv/app/build/cache"[..],
        ] {
            let decision =
                evaluate_remove_path(&set, &human(), target, Settings::default(), PASSWD);
            assert_eq!(decision.verdict, Verdict::Deny);
            assert_eq!(decision.denial, Some(DenialCode::OperationRefused));
        }
        let deep = evaluate_remove_path(
            &rules(
                r#"
[[operation]]
id = "shallow"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 1
max-entries = 4
"#,
            ),
            &human(),
            b"/srv/app/build/cache/obj",
            Settings::default(),
            "",
        );
        assert_eq!(deep.denial, Some(DenialCode::OperationRefused));
    }

    #[test]
    fn relative_components_refuse_dotdot_empty_and_overlong() {
        assert_eq!(
            check_relative(b"", 8).unwrap_err(),
            "the tree root is never removed"
        );
        assert_eq!(
            check_relative(b"..", 8).unwrap_err(),
            "target has an empty, current, or parent component"
        );
        assert_eq!(
            check_relative(b"a/.", 8).unwrap_err(),
            "target has an empty, current, or parent component"
        );
        assert_eq!(
            check_relative(b"a//b", 8).unwrap_err(),
            "target has an empty, current, or parent component"
        );
        let mut long = b"a/".to_vec();
        long.extend(std::iter::repeat_n(b'b', MAX_COMPONENT_BYTES + 1));
        assert_eq!(
            check_relative(&long, 8).unwrap_err(),
            "target component is too long"
        );
        assert_eq!(
            check_relative(b"a/b", 1).unwrap_err(),
            "target is deeper than max-depth"
        );
        assert_eq!(check_relative(b"cache", 1), Ok(()));
        assert_eq!(
            check_relative(b"a", 0).unwrap_err(),
            "target is deeper than max-depth"
        );
    }

    fn op_toml(id: &str, under: &str, extra: &str) -> String {
        format!(
            "[[operation]]\nid = \"{id}\"\nop = \"remove-path\"\nunder = \"{under}\"\nrecursive = true\nmax-depth = 2\nmax-entries = 4\n{extra}"
        )
    }

    fn load_err(text: &str) -> String {
        RuleSet::from_toml("50-remove-path.toml", text)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn a_malformed_operation_does_not_load() {
        let cases = [
            (op_toml("bad id", "/srv/a", ""), "id must be"),
            (op_toml("", "/srv/a", ""), "id must be"),
            (
                op_toml("a", "/srv/a", "").replace("max-depth = 2", "max-depth = 0"),
                "max-depth must be",
            ),
            (
                op_toml("a", "/srv/a", "").replace("max-depth = 2", "max-depth = 9999"),
                "max-depth must be",
            ),
            (
                op_toml("a", "/srv/a", "").replace("max-entries = 4", "max-entries = 0"),
                "max-entries must be",
            ),
            (
                op_toml("a", "/srv/a", "").replace("max-entries = 4", "max-entries = 99999999"),
                "max-entries must be",
            ),
            (op_toml("a", "/srv/a", "owners = []\n"), "owners is empty"),
            (
                op_toml("a", "/srv/a", "owners = [\"Not Valid\"]\n"),
                "not an account name",
            ),
            (
                op_toml("a", "/srv/a", "owners = [\"agent\", \"agent\"]\n"),
                "listed twice",
            ),
            (
                op_toml("a", "/srv/a", "harness = [\"BAD\"]\n"),
                "harness label",
            ),
            (
                op_toml("a", "/srv/a", "harness = [\"codex\", \"codex\"]\n"),
                "listed twice",
            ),
            (op_toml("a", "/srv/../etc", ""), "parent component"),
            (op_toml("a", "srv/a", ""), "not absolute"),
            (op_toml("a", "/srv//a", ""), "empty, current, or parent"),
            (
                op_toml("a", "/var", ""),
                "ancestor of an xudo protected prefix",
            ),
            (
                op_toml("a", "/var/lib", ""),
                "ancestor of an xudo protected prefix",
            ),
            (op_toml("a", "/root", ""), "protected system directory"),
            (op_toml("a", "/opt", ""), "protected system directory"),
            (
                op_toml("a", "/var/log", ""),
                "ancestor of an xudo protected prefix",
            ),
            (op_toml("a", "/var/mail", ""), "protected system directory"),
            (
                op_toml("a", "/srv/a", "owners = [\"root\"]\n"),
                "uid 0 (root)",
            ),
            (
                op_toml("a", &format!("/{}", "x".repeat(300)), ""),
                "component is longer",
            ),
            (
                op_toml("a", &format!("/{}", "x/".repeat(2100)), ""),
                "longer than 4096",
            ),
        ];
        for (text, needle) in cases {
            let message = load_err(&text);
            assert!(message.contains(needle), "{needle}: {message}");
        }
        assert_eq!(clean_absolute(b"/a\0b").unwrap_err(), "path contains NUL");
        assert_eq!(forbidden_under(b"/"), Some("the filesystem root"));
    }

    #[test]
    fn an_operation_id_is_unique_across_every_rule_kind() {
        let action = "[[action]]\nid = \"dup\"\ntier = \"svc-control\"\nexe = \"/usr/bin/systemctl\"\nargs = []\n";
        let deny = "[[deny]]\nid = \"dup\"\nreason = \"r\"\nprogram = [\"apt-get\"]\nall = []\n";
        let cases = [
            format!("{action}\n{}", op_toml("dup", "/srv/a", "")),
            format!("{deny}\n{}", op_toml("dup", "/srv/a", "")),
            format!(
                "{}\n{}",
                op_toml("dup", "/srv/a", ""),
                op_toml("dup", "/srv/b", "")
            ),
        ];
        for text in cases {
            let message = load_err(&text);
            assert!(message.contains("duplicate rule id dup"), "{message}");
        }
        let message = load_err(&format!(
            "{}\n{}",
            op_toml("one", "/srv/a", ""),
            op_toml("two", "/srv/a", "")
        ));
        assert!(message.contains("already the tree of one"), "{message}");
    }

    #[test]
    fn a_longer_tree_that_refuses_is_never_overridden_by_a_shorter_one() {
        let operations = [
            operation("wide", "/srv", 32),
            operation("narrow", "/srv/app/data", 1),
        ];
        assert_eq!(
            select(&operations, b"/srv/app/data/x/y").unwrap_err(),
            "target is deeper than max-depth"
        );
    }

    #[test]
    fn nested_operation_trees_do_not_load() {
        let text = format!(
            "{}\n{}",
            op_toml("wide", "/srv", ""),
            op_toml("narrow", "/srv/app/data", "")
        );
        assert!(load_err(&text).contains("nested under trees are not allowed"));
    }

    #[test]
    fn an_under_that_contains_xudos_state_is_refused() {
        for under in [b"/var".as_slice(), b"/var/lib", b"/var/log"] {
            let text = op_toml("state", std::str::from_utf8(under).unwrap(), "");
            assert!(load_err(&text).contains("protected"));
        }
    }

    #[test]
    fn the_operation_kind_names_itself_for_a_record() {
        assert_eq!(OpKind::RemovePath.as_str(), "remove-path");
    }

    #[test]
    fn an_omitted_owner_list_means_any_owner_but_root() {
        let any = operation("any", "/srv/a", 2);
        assert_eq!(resolve_owners(&any, PASSWD), Ok(OwnerPolicy::AnyButRoot));
    }

    #[test]
    fn an_owner_of_root_is_refused() {
        let text = op_toml("root-owner", "/srv/a", "owners = [\"root\"]\n");
        assert!(load_err(&text).contains("uid 0 (root)"));
        let mut direct = operation("direct-root-owner", "/srv/a", 2);
        direct.owners = Some(vec!["root".to_owned()]);
        assert_eq!(
            resolve_owners(&direct, PASSWD).unwrap_err(),
            "owners may not include uid 0 (root)"
        );
    }
}
