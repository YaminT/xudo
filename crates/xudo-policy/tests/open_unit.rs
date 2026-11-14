//! The open-unit lint matrix.
//!
//! `cargo miri test -p xudo-policy --lib` does not run this file. Each pattern
//! fixture compiles a regex and matches it against every lifecycle verb, which
//! is the miri overrun. The library test
//! `open_unit_lint_witnesses_each_matcher_kind` still reaches every matcher
//! arm, without a second regex per fixture. Native `cargo test` runs both.

#![allow(clippy::unwrap_used, clippy::panic)]

use xudo_policy::RuleSet;

fn loads(source: &str) -> RuleSet {
    RuleSet::from_toml("20-services.toml", source).unwrap()
}

fn lint_message(source: &str) -> Option<String> {
    loads(source)
        .open_unit_actions()
        .first()
        .map(xudo_policy::OpenUnitLint::message)
}

fn expect_lint(name: &str, source: &str, want: bool) {
    assert_eq!(lint_message(source).is_some(), want, "{name}");
}

#[test]
fn open_unit_lint_names_the_action_and_the_edit() {
    let set = loads(
        "\
[[action]]
id = \"xudo.svc.lifecycle\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"restart\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
    );
    let found = set.open_unit_actions();
    let lint = found.first().unwrap();
    assert_eq!(lint.id.as_str(), "xudo.svc.lifecycle");
    assert_eq!(lint.source.file, "20-services.toml");
    assert_eq!(lint.source.line, 2);
    let message = lint.message();
    assert_eq!(
        message,
        "xudo.svc.lifecycle at 20-services.toml:2: this rule can start or stop any unit: replace the unit matcher with a one-of list of your units"
    );
    assert!(set.has_systemctl_lifecycle_or_power());
    assert!(format!("{lint:?}").contains("xudo.svc.lifecycle"));
}

#[test]
fn open_unit_lint_flags_an_open_matcher_after_the_verb() {
    expect_lint(
        "one-of verb",
        "\
[[action]]
id = \"xudo.svc.lifecycle\"
tier = \"svc-control\"
exe = \"/usr/local/sbin/systemctl\"
args = [
  { name = \"verb\", matcher = { one-of = [\"status\", \"stop\"] } },
  { name = \"unit\", matcher = { name = \"service-unit-name\" } },
]
",
        true,
    );
    expect_lint(
        "power verb",
        "\
[[action]]
id = \"xudo.svc.power\"
tier = \"svc-control\"
exe = \"/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"poweroff\" } },
  { name = \"unit\", matcher = { pattern = \"[a-z.]+\" } },
]
",
        true,
    );
    expect_lint(
        "integer after the verb",
        "\
[[action]]
id = \"xudo.svc.range\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"start\" } },
  { name = \"unit\", matcher = { int-range = { lo = 1, hi = 2 } } },
]
",
        true,
    );
    expect_lint(
        "path after the verb",
        "\
[[action]]
id = \"xudo.svc.path\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"stop\" } },
  { name = \"unit\", matcher = { path-under = { prefix = \"/tmp\" } } },
]
",
        true,
    );
}

#[test]
fn open_unit_lint_accepts_a_finite_list_and_a_harmless_verb() {
    expect_lint(
        "harmless literal verb",
        "\
[[action]]
id = \"xudo.svc.reload-units\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"daemon-reload\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
        false,
    );
    expect_lint(
        "closed one-of",
        "\
[[action]]
id = \"xudo.svc.lifecycle\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"isolate\" } },
  { name = \"flag\", matcher = { literal = \"--no-block\" }, repeat = \"optional\" },
  { name = \"unit\", matcher = { one-of = [\"nginx.service\", \"example.service\"] }, repeat = { between = { min = 1, max = 4 } } },
]
",
        false,
    );
    expect_lint(
        "closed literal unit",
        "\
[[action]]
id = \"xudo.svc.lifecycle\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"start\" } },
  { name = \"unit\", matcher = { literal = \"nginx.service\" } },
]
",
        false,
    );
    expect_lint(
        "read-only verb",
        "\
[[action]]
id = \"xudo.svc.status\"
tier = \"diag-read\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { one-of = [\"status\", \"show\"] } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
        false,
    );
}

#[test]
fn open_unit_lint_ignores_the_wrong_exe_and_a_unit_before_the_verb() {
    let not_systemctl = "\
[[action]]
id = \"xudo.other\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl-helper\"
args = [
  { name = \"verb\", matcher = { literal = \"restart\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
";
    expect_lint("not systemctl", not_systemctl, false);
    assert!(!loads(not_systemctl).has_systemctl_lifecycle_or_power());
    expect_lint(
        "pattern that accepts no lifecycle verb",
        "\
[[action]]
id = \"xudo.svc.status-ish\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { pattern = \"status[0-9]*\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
        false,
    );
    // `unit-name` accepts none of the lifecycle verbs. Nothing after the
    // verb is open, so the matcher before the verb is not a finding.
    expect_lint(
        "unit matcher before the verb",
        "\
[[action]]
id = \"xudo.svc.backwards\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"unit\", matcher = { name = \"unit-name\" } },
  { name = \"verb\", matcher = { literal = \"restart\" } },
]
",
        false,
    );
    expect_lint(
        "verb only",
        "\
[[action]]
id = \"xudo.svc.poweroff\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { literal = \"reboot\" } },
]
",
        false,
    );
    assert!(!loads("# nothing\n").has_systemctl_lifecycle_or_power());
}

#[test]
fn open_unit_lint_flags_a_matcher_that_can_be_the_verb() {
    let pattern = "\
[[action]]
id = \"xudo.svc.pattern\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { pattern = \"[a-z-]+\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
";
    expect_lint(
        "pattern that accepts the verb, then an open unit",
        pattern,
        true,
    );
    assert!(loads(pattern).has_systemctl_lifecycle_or_power());
    expect_lint(
        "name kind that accepts the verb",
        "\
[[action]]
id = \"xudo.svc.name\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { name = \"hostname\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
        true,
    );
    expect_lint(
        "open matcher before the literal verb",
        "\
[[action]]
id = \"xudo.svc.before\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { pattern = \"[a-z-]+\" } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
  { name = \"again\", matcher = { literal = \"restart\" } },
]
",
        true,
    );
    expect_lint(
        "compat aliases",
        "\
[[action]]
id = \"xudo.svc.compat\"
tier = \"svc-control\"
exe = \"/usr/bin/systemctl\"
args = [
  { name = \"verb\", matcher = { one-of = [\"condrestart\", \"force-reload\"] } },
  { name = \"unit\", matcher = { name = \"unit-name\" } },
]
",
        true,
    );
}

#[test]
fn open_unit_lint_walks_every_matcher_before_the_verb() {
    let open = "  { name = \"unit\", matcher = { name = \"unit-name\" } },\n";
    let visited = format!(
        "\
[[action]]
id = \"xudo.svc.lifecycle\"
tier = \"svc-control\"
exe = \"/systemctl\"
args = [
  {{ name = \"pat\", matcher = {{ pattern = \"restart\" }} }},
  {{ name = \"num\", matcher = {{ int-range = {{ lo = 1, hi = 2 }} }} }},
  {{ name = \"path\", matcher = {{ path-under = {{ prefix = \"/srv\" }} }} }},
  {{ name = \"name\", matcher = {{ name = \"unit-name\" }} }},
  {{ name = \"empty\", matcher = {{ one-of = [] }} }},
  {{ name = \"verb\", matcher = {{ literal = \"exit\" }} }},
  {open}
]
[[action]]
id = \"xudo.svc.closed\"
tier = \"svc-control\"
exe = \"/usr/bin/true\"
args = [
  {{ name = \"verb\", matcher = {{ literal = \"start\" }} }},
  {open}
]
"
    );
    let set = loads(&visited);
    assert_eq!(set.open_unit_actions().len(), 1);
    assert!(set.has_systemctl_lifecycle_or_power());
}
