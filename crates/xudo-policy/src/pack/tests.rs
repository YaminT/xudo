#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unnecessary_wraps
)]

use super::*;
use crate::files::load_rule_files;
use crate::rule::RuleSetError;

/// A pack for codex: one passwordless restart, its tests and a near miss.
const NGINX: &str = r#"
[pack]
name = "nginx-ops"
version = "1.0.0"
for = ["codex"]

[[action]]
id = "pack.nginx.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
outcome = "allow"
gtfobins-waiver = "pager and unit-file shell escapes via systemctl: the rule pins --no-pager, the verb restart and the single unit nginx.service, so no pager, no editor and no caller-written unit can be reached through these operands"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { one-of = ["nginx.service"] } },
]

[[test]]
argv = ["/usr/bin/systemctl", "--no-pager", "restart", "nginx.service"]
expect = "allow"
action = "pack.nginx.restart"

[[test]]
argv = ["/usr/bin/systemctl", "--no-pager", "restart", "ssh.service"]
expect = "deny"
action = "pack.nginx.restart"
"#;

/// A plain rule file already installed.
const BASE: &str = r#"
[[action]]
id = "base.id"
tier = "diag-read"
exe = "/usr/bin/id"
"#;

fn file(name: &str, text: &str) -> RuleFile {
    RuleFile {
        name: name.as_bytes().to_vec(),
        bytes: text.as_bytes().to_vec(),
    }
}

fn registry(labels: &[&str]) -> Result<Vec<HarnessFile>, String> {
    Ok(labels
        .iter()
        .map(|label| HarnessFile {
            name: format!("{label}.toml").into_bytes(),
            bytes: format!(
                "label = \"{label}\"\nway = \"service\"\naccount = \"agent-{label}\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n"
            )
            .into_bytes(),
        })
        .collect())
}

/// Installing `text`, waivers allowed: what most tests review.
fn adding(text: &str) -> Change<'_> {
    Change::Add {
        pack: text.as_bytes(),
        allow_waivers: true,
    }
}

const REMOVING: Change<'static> = Change::Remove { name: "nginx-ops" };

fn parse(text: &str) -> Result<ParsedFile, RuleSetError> {
    RuleSet::parse_file("p.toml", text)
}

use crate::rule::ParsedFile;

#[test]
fn a_pack_fills_every_action_and_operation_from_for() {
    let parsed = parse(NGINX).unwrap();
    let header = parsed.pack.unwrap();
    assert_eq!(header.name, "nginx-ops");
    assert_eq!(header.file_name(), "pack-nginx-ops.toml");
    assert_eq!(parsed.rules.actions()[0].harness, vec!["codex".to_owned()]);
    assert!(parsed.rules.actions()[0].passwordless_for("codex"));
    assert!(!parsed.rules.actions()[0].passwordless_for("claude"));

    let op = r#"
[pack]
name = "tmp"
version = "1"
for = ["codex"]

[[operation]]
id = "pack.tmp.remove"
op = "remove-path"
under = "/srv/scratch"
recursive = false
max-depth = 1
max-entries = 1
owners = ["agent"]
outcome = "allow"
"#;
    let parsed = parse(op).unwrap();
    assert_eq!(
        parsed.rules.operations()[0].harness,
        vec!["codex".to_owned()]
    );
}

#[test]
fn a_pack_without_for_grants_no_harness() {
    let text = NGINX.replace("for = [\"codex\"]\n", "");
    // The action lists no harness and the pack gives it none, so it cannot
    // carry a waiver or an outcome for one: the file is refused whole.
    let error = parse(&text).unwrap_err();
    assert!(
        matches!(error, RuleSetError::BadGtfobinsWaiver { .. }),
        "{error}"
    );

    let bare = "[pack]\nname = \"ids\"\nversion = \"1\"\n\n[[action]]\nid = \"pack.id\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n";
    let parsed = parse(bare).unwrap();
    assert!(parsed.rules.actions()[0].harness.is_empty());
    let caps = capabilities(&parsed.rules);
    assert!(caps.iter().all(|c| c.audience == PASSWORD_PATH), "{caps:?}");

    // Naming a harness itself, in a pack for none, is widening.
    let named = format!("{bare}harness = [\"codex\"]\noutcome = \"allow\"\n");
    assert_eq!(
        parse(&named).unwrap_err(),
        RuleSetError::PackWidened {
            kind: "action",
            id: "pack.id".to_owned(),
            label: "codex".to_owned(),
            at: crate::rule::Source::new("p.toml", 6),
        }
    );
}

#[test]
fn an_action_cannot_widen_its_pack_for() {
    for listed in ["[\"claude\"]", "[\"codex\", \"claude\"]"] {
        let text = NGINX.replace(
            "outcome = \"allow\"\n",
            &format!("outcome = \"allow\"\nharness = {listed}\n"),
        );
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(&error, RuleSetError::PackWidened { kind: "action", label, .. } if label == "claude"),
            "{error}"
        );
        assert!(error.to_string().contains("may only narrow"), "{error}");
    }
    // Narrowing is allowed and kept as written.
    let two = NGINX.replace("for = [\"codex\"]", "for = [\"codex\", \"claude\"]");
    let narrowed = two.replace(
        "outcome = \"allow\"\n",
        "outcome = \"allow\"\nharness = [\"codex\"]\n",
    );
    let parsed = parse(&narrowed).unwrap();
    assert_eq!(parsed.rules.actions()[0].harness, vec!["codex".to_owned()]);
    assert_eq!(
        parse(&two).unwrap().rules.actions()[0].harness,
        vec!["codex".to_owned(), "claude".to_owned()]
    );

    let op = "[pack]\nname = \"tmp\"\nversion = \"1\"\nfor = [\"codex\"]\n\n[[operation]]\nid = \"pack.tmp.remove\"\nop = \"remove-path\"\nunder = \"/srv/scratch\"\nrecursive = false\nmax-depth = 1\nmax-entries = 1\nowners = [\"agent\"]\noutcome = \"allow\"\nharness = [\"claude\"]\n";
    let error = parse(op).unwrap_err();
    assert!(
        matches!(
            &error,
            RuleSetError::PackWidened {
                kind: "operation",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_pack_action_still_needs_an_outcome_and_a_safe_shape() {
    let no_outcome = NGINX.replace("outcome = \"allow\"\n", "");
    assert!(matches!(
        parse(&no_outcome).unwrap_err(),
        RuleSetError::HarnessWithoutOutcome { .. }
    ));
    let path_under = "[pack]\nname = \"cat\"\nversion = \"1\"\nfor = [\"codex\"]\n\n[[action]]\nid = \"pack.ls\"\ntier = \"diag-read\"\nexe = \"/usr/bin/stat\"\noutcome = \"allow\"\nargs = [{ name = \"p\", matcher = { path-under = { prefix = \"/srv\" } } }]\n";
    assert!(matches!(
        parse(path_under).unwrap_err(),
        RuleSetError::DangerousHarnessShape { .. }
    ));
}

#[test]
fn a_bad_pack_header_fails_to_load() {
    let header = |body: &str| format!("[pack]\n{body}\n");
    for body in [
        "name = \"Nginx\"\nversion = \"1\"",
        "name = \"-x\"\nversion = \"1\"",
        "name = \"x\"\nversion = \"\"",
        "name = \"x\"\nversion = \"1 2\"",
        "name = \"x\"\nversion = \"123456789012345678901234567890123\"",
        "name = \"x\"\nversion = \"1\"\nfor = [\"Codex\"]",
        "name = \"x\"\nversion = \"1\"\nfor = [\"codex\", \"codex\"]",
    ] {
        let error = parse(&header(body)).unwrap_err();
        assert!(
            matches!(error, RuleSetError::BadPack { .. }),
            "{body}: {error}"
        );
        assert!(
            error.to_string().starts_with("rule file p.toml: pack "),
            "{error}"
        );
    }
    for body in [
        "name = \"x\"\nversion = \"1\"\nauto-update = true",
        "name = \"x\"",
        "version = \"1\"",
    ] {
        assert!(
            matches!(
                parse(&header(body)).unwrap_err(),
                RuleSetError::Parse { .. }
            ),
            "{body}"
        );
    }
    assert!(parse(&header("name = \"x\"\nversion = \"1.0+rc_2-a\"")).is_ok());
}

#[test]
fn the_pack_name_and_version_enter_the_generation() {
    let generation = |text: &str| {
        load_rule_files(vec![file("pack-x.toml", text)])
            .unwrap()
            .generation
    };
    let one = generation(NGINX);
    assert_ne!(one, generation(&NGINX.replace("1.0.0", "1.0.1")));
    assert_ne!(one, generation(&NGINX.replace("nginx-ops", "nginx-two")));
    // An empty pack is still hashed, and a file without a header is not.
    let empty = "[pack]\nname = \"x\"\nversion = \"1\"\n";
    assert_ne!(
        load_rule_files(vec![]).unwrap().generation,
        generation(empty)
    );
    let loaded = load_rule_files(vec![file("pack-x.toml", NGINX), file("10.toml", BASE)]).unwrap();
    assert_eq!(loaded.packs.len(), 1);
    assert_eq!(loaded.packs[0].file, "pack-x.toml");
    assert_eq!(loaded.packs[0].header.name, "nginx-ops");
}

#[test]
fn two_files_cannot_be_the_same_pack() {
    let other = "[pack]\nname = \"other\"\nversion = \"1\"\n";
    assert_eq!(
        load_rule_files(vec![file("a.toml", NGINX), file("b.toml", other)])
            .unwrap()
            .packs
            .len(),
        2
    );
    let again = NGINX.replace("pack.nginx.restart", "pack.nginx.again");
    let error = load_rule_files(vec![file("b.toml", &again), file("a.toml", NGINX)]).unwrap_err();
    assert_eq!(
        error,
        RuleFilesError::DuplicatePack {
            name: "nginx-ops".to_owned(),
            first: "a.toml".to_owned(),
            second: "b.toml".to_owned(),
        }
    );
    assert_eq!(
        error.to_string(),
        "pack nginx-ops is in both a.toml and b.toml"
    );
}

#[test]
fn header_of_names_why_a_file_is_not_a_pack() {
    assert_eq!(header_of(b"\xff").unwrap_err(), PackRefusal::NotUtf8);
    assert!(matches!(
        header_of(b"[nope]").unwrap_err(),
        PackRefusal::Parse(_)
    ));
    assert_eq!(
        header_of(BASE.as_bytes()).unwrap_err(),
        PackRefusal::NotAPack
    );
    assert_eq!(header_of(NGINX.as_bytes()).unwrap().version, "1.0.0");
    assert_eq!(file_name("x"), "pack-x.toml");
}

#[test]
fn digest_is_sha256_in_hex() {
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn the_diff_names_every_new_capability() {
    let before = vec![file("10.toml", BASE)];
    let after = vec![file("10.toml", BASE), file("pack-nginx-ops.toml", NGINX)];
    let review = review(
        before.clone(),
        after.clone(),
        &registry(&["codex"]),
        adding(NGINX),
    )
    .unwrap();
    let what =
        "pack.nginx.restart: /usr/bin/systemctl --no-pager restart <one of [\"nginx.service\"]>";
    assert_eq!(
        review.gains,
        vec![
            Capability {
                audience: "codex".to_owned(),
                how: "no password",
                what: what.to_owned(),
                program: "/usr/bin/systemctl".to_owned(),
            },
            Capability {
                audience: PASSWORD_PATH.to_owned(),
                how: "password",
                what: what.to_owned(),
                program: "/usr/bin/systemctl".to_owned(),
            },
        ]
    );
    assert!(review.losses.is_empty());
    assert_eq!(
        review.lines(),
        vec![
            format!("codex gains (no password): {what}"),
            format!("password path gains (password): {what}"),
        ]
    );

    // Removing it is the mirror image.
    let back = super::review(after, before, &registry(&["codex"]), REMOVING).unwrap();
    assert!(back.gains.is_empty());
    assert_eq!(back.losses, review.gains);
    assert_eq!(
        back.lines()[0],
        format!("codex loses (no password): {what}")
    );

    // A changed operand is a loss and a gain, never silent.
    let wider = NGINX.replace(
        "[\"nginx.service\"]",
        "[\"nginx.service\", \"php.service\"]",
    );
    let changed = super::review(
        vec![file("p.toml", NGINX)],
        vec![file("p.toml", &wider)],
        &registry(&["codex"]),
        adding(&wider),
    )
    .unwrap();
    assert_eq!((changed.gains.len(), changed.losses.len()), (2, 2));
    assert!(changed.gains[0].what.contains("php.service"));
}

#[test]
fn every_shape_and_outcome_reads_in_the_diff() {
    let text = r#"
[pack]
name = "mixed"
version = "1"
for = ["codex"]

[[action]]
id = "pack.journal"
tier = "diag-read"
exe = "/usr/bin/uptime"
outcome = "ask-human"
args = [
  { name = "a", matcher = { literal = "-p" }, repeat = "optional" },
  { name = "b", matcher = { int-range = { lo = 1, hi = 9 } }, repeat = { between = { min = 0, max = 2 } } },
]

[[operation]]
id = "pack.tmp"
op = "remove-path"
under = "/srv/scratch"
recursive = false
max-depth = 1
max-entries = 1
owners = ["agent"]
outcome = "allow"
"#;
    let caps = capabilities(&parse(text).unwrap().rules);
    let lines: Vec<String> = caps
        .iter()
        .map(|c| format!("{} {} {}", c.audience, c.how, c.what))
        .collect();
    assert_eq!(
        lines,
        vec![
            "codex asks a human pack.journal: /usr/bin/uptime [-p] <integer in 1..=9>{0,2}",
            "codex no password pack.tmp: remove-path under /srv/scratch; recursive false; max-depth 1; max-entries 1; owners [\"agent\"]",
            "password path password pack.journal: /usr/bin/uptime [-p] <integer in 1..=9>{0,2}",
            "password path password pack.tmp: remove-path under /srv/scratch; recursive false; max-depth 1; max-entries 1; owners [\"agent\"]",
        ]
    );
}

#[test]
fn a_pack_with_a_failing_test_is_refused_by_review() {
    let failing = format!(
        "{NGINX}\n[[test]]\nargv = [\"/usr/bin/systemctl\", \"--no-pager\", \"restart\", \"php.service\"]\nexpect = \"allow\"\n"
    );
    let refusal = review(
        vec![],
        vec![file("pack-nginx-ops.toml", &failing)],
        &registry(&["codex"]),
        adding(&failing),
    )
    .unwrap_err();
    let PackRefusal::Problems(found) = &refusal else {
        panic!("{refusal}");
    };
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("does not hold"), "{found:?}");
    assert!(
        refusal
            .to_string()
            .starts_with("after the change the rules fail 1 check(s)")
    );
}

#[test]
fn review_refuses_every_check_xudo_check_would_fail() {
    let codex = registry(&["codex"]);
    let problems = |after: Vec<RuleFile>, registry: &Result<Vec<HarnessFile>, String>| match review(
        vec![],
        after,
        registry,
        adding(NGINX),
    )
    .unwrap_err()
    {
        PackRefusal::Problems(found) => found.join("\n"),
        other => panic!("{other}"),
    };
    // No near miss.
    let no_near_miss = NGINX.replace("\"ssh.service\"", "\"nginx.service\", \"x\"");
    assert!(problems(vec![file("p.toml", &no_near_miss)], &codex).contains("near-miss"));
    // A harness nobody registered.
    assert!(problems(vec![file("p.toml", NGINX)], &registry(&[])).contains("not in the registry"));
    // A registry that did not load.
    let fault = problems(vec![file("p.toml", NGINX)], &Err("damaged".to_owned()));
    assert!(
        fault.contains("registry failed to load: damaged"),
        "{fault}"
    );
    // A rule the deny-list makes useless.
    let shell = "[[action]]\nid = \"sh\"\ntier = \"diag-read\"\nexe = \"/bin/sh\"\n";
    assert!(problems(vec![file("s.toml", shell)], &codex).contains("deny-list refuses"));
    // A systemctl rule that can restart any unit.
    let open = "[[action]]\nid = \"open\"\ntier = \"svc-control\"\nexe = \"/usr/bin/systemctl\"\nargs = [{ name = \"v\", matcher = { literal = \"restart\" } }, { name = \"u\", matcher = { name = \"unit-name\" } }]\n";
    assert!(problems(vec![file("o.toml", open)], &codex).contains("any unit"));
    // A multicall binary with no pinned applet.
    let multi = "[[action]]\nid = \"multi\"\ntier = \"diag-read\"\nexe = \"/usr/bin/coreutils\"\nargs = [{ name = \"a\", matcher = { one-of = [\"--coreutils-prog=sh\"] } }]\n";
    assert!(problems(vec![file("m.toml", multi)], &codex).contains("pin its applet"));
}

#[test]
fn review_refuses_rules_that_do_not_load() {
    let broken = vec![file("x.toml", "[[action]]\n")];
    assert!(matches!(
        review(broken.clone(), vec![], &registry(&[]), REMOVING).unwrap_err(),
        PackRefusal::Current(_)
    ));
    let refusal = review(vec![], broken, &registry(&[]), REMOVING).unwrap_err();
    assert!(matches!(refusal, PackRefusal::Load(_)));
    assert!(
        refusal
            .to_string()
            .starts_with("after the change the rules would not load")
    );
    assert!(
        PackRefusal::Current(RuleFilesError::TooManyTests { limit: 1 })
            .to_string()
            .starts_with("the installed rules do not load")
    );
    assert_eq!(
        PackRefusal::NotAPack.to_string(),
        "the file has no [pack] header, so it is not a rule pack"
    );
    assert_eq!(
        PackRefusal::NotUtf8.to_string(),
        "the pack is not UTF-8 text"
    );
}

/// A plain rule file: codex may run `uptime -p` with no password.
const UPTIME: &str = r#"
[[action]]
id = "base.uptime"
tier = "diag-read"
exe = "/usr/bin/uptime"
harness = ["codex"]
outcome = "allow"
args = [{ name = "p", matcher = { literal = "-p" } }]

[[test]]
argv = ["/usr/bin/uptime", "-p"]
expect = "allow"
action = "base.uptime"

[[test]]
argv = ["/usr/bin/uptime", "-s"]
expect = "deny"
action = "base.uptime"
"#;

/// A pack that makes codex ask a human for the same command.
const STRICT: &str = r#"
[pack]
name = "strict"
version = "1"
for = ["codex"]

[[action]]
id = "pack.uptime"
tier = "diag-read"
exe = "/usr/bin/uptime"
outcome = "ask-human"
args = [{ name = "p", matcher = { literal = "-p" } }]

[[test]]
argv = ["/usr/bin/uptime", "-p"]
expect = "allow"
action = "pack.uptime"

[[test]]
argv = ["/usr/bin/uptime", "-s"]
expect = "deny"
action = "pack.uptime"
"#;

/// A pack of refusals only: `id -g` is refused to everyone.
const REFUSALS: &str = r#"
[pack]
name = "refusals"
version = "1"

[[deny]]
id = "pack.no-groups"
reason = "no group listing"
program = ["id"]
all = [{ any-arg = ["-g"] }]

[[deny]]
id = "pack.no-telnetd"
reason = "no telnet server"
program = ["apt-get"]
all = [{ any-deb-name = ["telnetd"] }]

[[test]]
argv = ["/usr/bin/id", "-g"]
expect = "deny"
deny-rule = "pack.no-groups"
"#;

/// `id` with `-u` or `-g`, on the password path.
const IDS_BASE: &str = r#"
[[action]]
id = "base.id"
tier = "diag-read"
exe = "/usr/bin/id"
args = [{ name = "which", matcher = { one-of = ["-u", "-g"] } }]
"#;

#[test]
fn removing_a_pack_of_deny_rules_is_a_loud_gain_for_everyone() {
    let before = vec![
        file("10-ids.toml", IDS_BASE),
        file("pack-refusals.toml", REFUSALS),
    ];
    let after = vec![file("10-ids.toml", IDS_BASE)];
    let removed = review(
        before.clone(),
        after.clone(),
        &registry(&[]),
        Change::Remove { name: "refusals" },
    )
    .unwrap();
    assert!(removed.losses.is_empty(), "{:?}", removed.losses);
    assert_eq!(
        removed.lines(),
        vec![
            "everyone gains, a refusal goes: pack.no-groups: id when an argument is one of [\"-g\"]",
            "everyone gains, a refusal goes: pack.no-telnetd: apt-get when a package is one of [\"telnetd\"]",
        ]
    );
    // The engine agrees: `id -g` was refused and now runs.
    assert_eq!(
        removed.effect_lines(),
        vec!["password path gains: /usr/bin/id -g was refused, now password"]
    );

    // Adding them is the mirror: a new refusal is a loss, never a gain.
    let added = review(after, before, &registry(&[]), adding(REFUSALS)).unwrap();
    assert!(added.gains.is_empty(), "{:?}", added.gains);
    assert_eq!(
        added.lines()[0],
        "everyone loses, a new refusal: pack.no-groups: id when an argument is one of [\"-g\"]"
    );
    assert_eq!(
        added.effect_lines(),
        vec!["password path loses: /usr/bin/id -g was password, now refused"]
    );

    // An upgrade that drops one deny rule is a gain too, never silent.
    let fewer = REFUSALS
        .split("[[deny]]\nid = \"pack.no-telnetd\"")
        .next()
        .unwrap()
        .to_owned()
        + "\n[[test]]\nargv = [\"/usr/bin/id\", \"-g\"]\nexpect = \"deny\"\ndeny-rule = \"pack.no-groups\"\n";
    let upgrade = review(
        vec![
            file("10-ids.toml", IDS_BASE),
            file("pack-refusals.toml", REFUSALS),
        ],
        vec![
            file("10-ids.toml", IDS_BASE),
            file("pack-refusals.toml", &fewer),
        ],
        &registry(&[]),
        adding(&fewer),
    )
    .unwrap();
    assert_eq!(upgrade.gains.len(), 1, "{:?}", upgrade.gains);
    assert!(upgrade.gains[0].what.starts_with("pack.no-telnetd"));
    assert_eq!(upgrade.gains[0].audience, EVERYONE);
}

#[test]
fn an_upgrade_that_adds_env_allow_shows() {
    let with_env = NGINX.replace(
        "outcome = \"allow\"\n",
        "outcome = \"allow\"\nenv-allow = [\"TERM\"]\n",
    );
    let upgrade = review(
        vec![file("pack-nginx-ops.toml", NGINX)],
        vec![file("pack-nginx-ops.toml", &with_env)],
        &registry(&["codex"]),
        adding(&with_env),
    )
    .unwrap();
    assert_eq!((upgrade.gains.len(), upgrade.losses.len()), (2, 2));
    assert!(
        upgrade.lines()[0].ends_with("; env-allow [\"TERM\"]"),
        "{:?}",
        upgrade.lines()
    );
}

#[test]
fn every_operation_limit_change_shows() {
    let op = |recursive: bool, depth: u32, entries: u32, owners: &str| {
        format!(
            "[pack]\nname = \"tmp\"\nversion = \"1\"\nfor = [\"codex\"]\n\n[[operation]]\nid = \"pack.tmp\"\nop = \"remove-path\"\nunder = \"/srv/scratch\"\nrecursive = {recursive}\nmax-depth = {depth}\nmax-entries = {entries}\nowners = {owners}\noutcome = \"allow\"\n"
        )
    };
    let base = op(false, 1, 1, "[\"agent\"]");
    for wider in [
        op(true, 1, 1, "[\"agent\"]"),
        op(false, 9, 1, "[\"agent\"]"),
        op(false, 1, 99, "[\"agent\"]"),
        op(false, 1, 1, "[\"agent\", \"www-data\"]"),
    ] {
        let change = review(
            vec![file("pack-tmp.toml", &base)],
            vec![file("pack-tmp.toml", &wider)],
            &registry(&["codex"]),
            adding(&wider),
        )
        .unwrap();
        assert_eq!((change.gains.len(), change.losses.len()), (2, 2), "{wider}");
        // An operation runs no program: no other rule can overlap its loss.
        assert!(change.overlaps.is_empty());
    }
    // Owners left out read as what they mean.
    let any = "[[operation]]\nid = \"tmp\"\nop = \"remove-path\"\nunder = \"/srv/scratch\"\nrecursive = false\nmax-depth = 1\nmax-entries = 1\n";
    let caps = capabilities(&parse(any).unwrap().rules);
    assert!(
        caps.iter().all(|c| c.what.ends_with("owners any but root")),
        "{caps:?}"
    );
}

#[test]
fn every_setting_that_changes_an_action_reads_in_its_line() {
    let text = r#"
[[action]]
id = "a.always"
tier = "diag-read"
exe = "/usr/bin/uptime"
confirm = "always"

[[action]]
id = "a.never"
tier = "diag-read"
exe = "/usr/bin/uptime"
confirm = "never"
args = [{ name = "p", matcher = { literal = "-p" } }]

[[action]]
id = "a.human"
tier = "diag-read"
exe = "/usr/bin/uptime"
agent-allowed = false
args = [{ name = "s", matcher = { literal = "-s" } }]

[[action]]
id = "a.critical"
tier = "critical"
exe = "/usr/bin/uptime"
args = [{ name = "v", matcher = { literal = "-V" } }]
"#;
    let whats: Vec<String> = capabilities(&parse(text).unwrap().rules)
        .into_iter()
        .map(|c| c.what)
        .collect();
    assert_eq!(
        whats,
        vec![
            "a.always: /usr/bin/uptime; confirm always",
            "a.critical: /usr/bin/uptime -V; tier critical",
            "a.human: /usr/bin/uptime -s; agent-allowed false",
            "a.never: /usr/bin/uptime -p; confirm never",
        ]
    );
}

#[test]
fn removing_a_stricter_overlapping_ask_human_prints_as_a_gain() {
    let codex = registry(&["codex"]);
    let base = vec![file("10-base.toml", UPTIME)];
    let both = vec![
        file("10-base.toml", UPTIME),
        file("pack-strict.toml", STRICT),
    ];
    let removed = review(
        both.clone(),
        base.clone(),
        &codex,
        Change::Remove { name: "strict" },
    )
    .unwrap();
    // By rule text it is a loss; the review says it may widen and what now
    // applies.
    assert_eq!(
        removed.lines(),
        vec![
            "codex loses (asks a human): pack.uptime: /usr/bin/uptime -p; may widen: now base.uptime applies",
            "password path loses (password): pack.uptime: /usr/bin/uptime -p; may widen: now base.uptime applies",
        ]
    );
    // And the engine says what it is: a gain.
    assert_eq!(
        removed.effect_lines(),
        vec!["codex gains: /usr/bin/uptime -p was queued for a human, now no password"]
    );

    // Installing it narrows, and says so.
    let added = review(base, both, &codex, adding(STRICT)).unwrap();
    assert_eq!(
        added.effect_lines(),
        vec!["codex loses: /usr/bin/uptime -p was no password, now queued for a human"]
    );
}

#[test]
fn every_decision_has_a_word_ranked_by_what_it_allows() {
    let rules = RuleSet::from_toml(
        "d.toml",
        "[[action]]\nid = \"c\"\ntier = \"diag-read\"\nexe = \"/usr/bin/uptime\"\nconfirm = \"always\"\n",
    )
    .unwrap();
    let human = CallerFacts::new(Classification::Human, 1000);
    let program = Arg::from("/usr/bin/uptime");
    let ask = |argv: &[&str]| {
        evaluate_command(
            &rules,
            &human,
            &program,
            &Argv::new(argv.to_vec()),
            Settings::default(),
        )
    };
    assert_eq!(decided(&ask(&[]), false), ("confirmed by a human", 2));
    assert_eq!(decided(&ask(&["-x"]), false), (REFUSED, 0));
}

#[test]
fn a_waiver_is_refused_unless_allowed_and_always_shown() {
    let after = vec![file("pack-nginx-ops.toml", NGINX)];
    let refusal = review(
        vec![],
        after.clone(),
        &registry(&["codex"]),
        Change::Add {
            pack: NGINX.as_bytes(),
            allow_waivers: false,
        },
    )
    .unwrap_err();
    let PackRefusal::Waivers(found) = &refusal else {
        panic!("{refusal}");
    };
    assert_eq!(found.len(), 1);
    assert!(
        found[0].starts_with("pack.nginx.restart: pager and unit-file shell escapes"),
        "{found:?}"
    );
    assert!(
        refusal
            .to_string()
            .starts_with("the pack waives 1 GTFOBins refusal(s) (pack.nginx.restart: pager"),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("--allow-waivers"));

    let allowed = review(vec![], after.clone(), &registry(&["codex"]), adding(NGINX)).unwrap();
    assert_eq!(allowed.waivers, *found);
    // Taking a waiver away needs no flag.
    let removed = review(after, vec![], &registry(&["codex"]), REMOVING).unwrap();
    assert!(removed.waivers.is_empty());
}

#[test]
fn the_token_binds_the_pack_the_flag_and_the_rules_it_was_judged_against() {
    let codex = registry(&["codex"]);
    let token = |before: Vec<RuleFile>, pack: &str, registry, allow_waivers| {
        let mut after: Vec<RuleFile> = before.clone();
        after.push(file("pack-refusals.toml", pack));
        let change = Change::Add {
            pack: pack.as_bytes(),
            allow_waivers,
        };
        review(before, after, registry, change).unwrap().token
    };
    let base = || vec![file("10.toml", IDS_BASE)];
    let reviewed = token(base(), REFUSALS, &codex, false);
    assert_eq!(reviewed.len(), 64);
    // The same change against the same rules is the same token.
    assert_eq!(token(base(), REFUSALS, &codex, false), reviewed);
    // Another pack, the flag, the rules, or the registry: another token.
    let other = REFUSALS.replace("version = \"1\"", "version = \"2\"");
    for different in [
        token(base(), &other, &codex, false),
        token(base(), REFUSALS, &codex, true),
        token(
            vec![file("10.toml", IDS_BASE), file("20.toml", UPTIME)],
            REFUSALS,
            &codex,
            false,
        ),
        token(base(), REFUSALS, &registry(&["codex", "claude"]), false),
    ] {
        assert_ne!(different, reviewed);
    }
    // Removing is never the token of adding.
    let installed = vec![file("pack-nginx-ops.toml", NGINX)];
    let removal = review(installed.clone(), vec![], &codex, REMOVING).unwrap();
    assert_ne!(removal.token, reviewed);
    let other_name = review(installed, vec![], &codex, Change::Remove { name: "x" }).unwrap();
    assert_ne!(other_name.token, removal.token);
}

#[test]
fn only_a_pack_xudo_installed_is_taken_away() {
    let ours = RuleFile {
        name: b"pack-ids.toml".to_vec(),
        bytes: installed_bytes(b"[pack]\n"),
    };
    assert!(installed_by_xudo(&ours.bytes));
    assert!(PACK_MARKER.starts_with("# Managed by xudo."));
    let others = vec![file("10.toml", BASE), ours.clone()];
    assert_eq!(
        without_pack(&others, "ids"),
        Some(vec![file("10.toml", BASE)])
    );
    // A hand-written file of the same name, a sudoers-style header, a missing
    // pack, and a name that is not one.
    let hand = vec![file("pack-ids.toml", "[pack]\n")];
    let sudoers = vec![file("pack-ids.toml", "# Managed by xudo. Do not edit\n")];
    assert_eq!(without_pack(&hand, "ids"), None);
    assert_eq!(without_pack(&sudoers, "ids"), None);
    assert_eq!(without_pack(&others, "web"), None);
    let traversal = vec![RuleFile {
        name: b"pack-../x.toml".to_vec(),
        bytes: installed_bytes(b""),
    }];
    assert_eq!(without_pack(&traversal, "../x"), None);

    // Installing replaces the file of the pack's name and keeps the rest.
    let header = header_of(REFUSALS.as_bytes()).unwrap();
    let old = file("pack-refusals.toml", "old");
    let installed = with_pack(&[file("10.toml", BASE), old], &header, REFUSALS.as_bytes());
    assert_eq!(installed.len(), 2);
    assert_eq!(installed[1].bytes, installed_bytes(REFUSALS.as_bytes()));
}
