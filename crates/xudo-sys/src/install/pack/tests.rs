#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unnecessary_wraps
)]

use super::*;
use crate::install::enrol::tests::Machine;

const NGINX: &str = r#"[pack]
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

const BASE: &str = "[[action]]\nid = \"base.id\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n";
const PATH: &str = "/etc/xudo/rules.d/pack-nginx-ops.toml";
const CODEX: &str = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";

/// A human's login session, as the kernel reports it.
fn session() -> std::io::Result<Vec<u8>> {
    Ok(b"0::/user.slice/user-1000.slice/session-3.scope\n".to_vec())
}

fn host() -> Machine {
    Machine::root()
        .with_file("/etc/xudo/rules.d/10-base.toml", BASE)
        .with_file("/etc/xudo/harnesses.d/codex.toml", CODEX)
}

fn request(text: &str) -> PackRequest {
    PackRequest {
        bytes: text.as_bytes().to_vec(),
        reviewed: digest(text.as_bytes()),
    }
}

fn wrote_nothing(machine: &Machine) -> bool {
    !machine
        .calls()
        .iter()
        .any(|call| call.starts_with("write_candidate") || call.starts_with("install"))
}

#[test]
fn a_reviewed_pack_is_installed_with_the_marker_by_rename() {
    let machine = host();
    let report = add_pack(&request(NGINX), session(), &machine, &machine).unwrap();
    assert_eq!(report.path, PATH);
    let written = machine.files.borrow()[PATH].clone();
    assert!(written.starts_with(MANAGED_MARKER), "{written}");
    assert!(written.ends_with(NGINX));
    assert_eq!(
        machine.calls(),
        vec![
            format!("write_candidate {PATH}.candidate"),
            format!("install {PATH}"),
        ]
    );
    assert!(report.review.lines()[0].starts_with("codex gains (no password): pack.nginx.restart"));

    // A new version replaces the file xudo wrote, and says what changed.
    let wider = NGINX.replace("1.0.0", "1.1.0").replace(
        "[\"nginx.service\"]",
        "[\"nginx.service\", \"php.service\"]",
    );
    let report = add_pack(&request(&wider), session(), &machine, &machine).unwrap();
    assert!(machine.files.borrow()[PATH].ends_with(&wider));
    assert_eq!(
        (report.review.gains.len(), report.review.losses.len()),
        (2, 2)
    );
}

#[test]
fn a_pack_with_a_failing_test_is_never_installed() {
    let failing = format!(
        "{NGINX}\n[[test]]\nargv = [\"/usr/bin/systemctl\", \"--no-pager\", \"restart\", \"php.service\"]\nexpect = \"allow\"\n"
    );
    let machine = host();
    let error = add_pack(&request(&failing), session(), &machine, &machine).unwrap_err();
    assert!(
        matches!(&error, PackError::Refused(PackRefusal::Problems(found)) if found[0].contains("does not hold")),
        "{error}"
    );
    assert!(
        error.to_string().ends_with("; nothing was changed"),
        "{error}"
    );
    assert!(wrote_nothing(&machine));
    assert!(!machine.files.borrow().contains_key(PATH));
}

#[test]
fn an_agent_cannot_install_a_pack() {
    for cgroup in [
        "0::/xudo.slice/xudo-agent@codex.service\n",
        "0::/xudo.slice/agent-0123456789abcdef0123456789abcdef.scope\n",
        "0::/xudo.slice\n",
        // cgroup v1 beside v2: any one line inside the slice is enough.
        "12:pids:/user.slice\n0::/xudo.slice/xudo-agent@codex.service\n",
    ] {
        let machine = host().with_file(
            PATH,
            &String::from_utf8(installed_bytes(NGINX.as_bytes())).unwrap(),
        );
        let read = || Ok(cgroup.as_bytes().to_vec());
        assert_eq!(
            add_pack(&request(NGINX), read(), &machine, &machine).unwrap_err(),
            PackError::AgentBox,
            "{cgroup:?}"
        );
        assert_eq!(
            remove_pack("nginx-ops", read(), &machine, &machine).unwrap_err(),
            PackError::AgentBox
        );
        assert!(machine.calls().is_empty(), "{:?}", machine.calls());
    }
    // A slice that merely starts with the same letters is not the box.
    let machine = host();
    let lookalike = Ok(b"0::/xudo.slicey/x.scope\n".to_vec());
    assert!(add_pack(&request(NGINX), lookalike, &machine, &machine).is_ok());
    assert!(
        PackError::AgentBox
            .to_string()
            .contains("a harness cannot install or remove a rule pack")
    );
}

#[test]
fn an_unreadable_cgroup_refuses() {
    for cgroup in [
        Err(std::io::Error::other("no /proc")),
        Ok(Vec::new()),
        Ok(b"garbage\n".to_vec()),
        Ok(b"0::relative\n".to_vec()),
    ] {
        let machine = host();
        let error = add_pack(&request(NGINX), cgroup, &machine, &machine).unwrap_err();
        assert!(matches!(error, PackError::CgroupUnknown(_)), "{error}");
        assert!(
            error.to_string().starts_with("cannot tell whether"),
            "{error}"
        );
        assert!(machine.calls().is_empty());
    }
}

#[test]
fn only_root_installs_or_removes() {
    let mut machine = host();
    machine.uid = 1000;
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert_eq!(error, PackError::NotRoot { uid: 1000 });
    assert_eq!(
        error.to_string(),
        "this needs root (effective uid 1000); nothing was changed"
    );
    assert_eq!(
        remove_pack("nginx-ops", session(), &machine, &machine).unwrap_err(),
        PackError::NotRoot { uid: 1000 }
    );
}

#[test]
fn the_root_side_re_validates_before_rename() {
    // Changed after the operator's review, even into a pack that still passes.
    let machine = host();
    let mut changed = request(NGINX);
    changed.bytes = NGINX.replace("1.0.0", "1.0.1").into_bytes();
    let error = add_pack(&changed, session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");
    assert!(error.to_string().contains("changed after it was reviewed"));
    assert!(wrote_nothing(&machine));

    // The same bytes, but root's rules moved on since the review: an action
    // with the pack's id now exists, so the two cannot load together.
    let clash = NGINX
        .split("[[test]]")
        .next()
        .unwrap()
        .replace("name = \"nginx-ops\"", "name = \"other\"");
    let machine = host().with_file("/etc/xudo/rules.d/20-clash.toml", &clash);
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(
        matches!(error, PackError::Refused(PackRefusal::Load(_))),
        "{error}"
    );
    assert!(wrote_nothing(&machine));

    // The harness left the registry after the review.
    let machine = Machine::root().with_file("/etc/xudo/rules.d/10-base.toml", BASE);
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(error.to_string().contains("not in the registry"), "{error}");
    assert!(wrote_nothing(&machine));

    // A registry root cannot trust is a fault, which refuses.
    let machine = host();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d".to_owned());
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(
        error.to_string().contains("registry failed to load"),
        "{error}"
    );
    let machine = host();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d/codex.toml".to_owned());
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(
        error.to_string().contains("registry failed to load"),
        "{error}"
    );
}

#[test]
fn an_operators_file_is_never_replaced() {
    let machine = host().with_file(PATH, NGINX);
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(
        matches!(&error, PackError::Install(InstallError::NotOurs { path, .. }) if path == PATH),
        "{error}"
    );
    assert!(wrote_nothing(&machine));
    assert_eq!(machine.files.borrow()[PATH], NGINX);
    assert_eq!(
        remove_pack("nginx-ops", session(), &machine, &machine).unwrap_err(),
        PackError::NotInstalled("nginx-ops".to_owned())
    );
}

#[test]
fn a_failed_rename_takes_the_candidate_back() {
    let machine = host().failing("install");
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Install(_)), "{error}");
    assert!(
        machine
            .calls()
            .contains(&format!("discard {PATH}.candidate"))
    );
    let machine = host().failing("write_candidate");
    assert!(matches!(
        add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err(),
        PackError::Install(_)
    ));
}

#[test]
fn what_cannot_be_read_refuses() {
    let machine = Machine::root();
    let error = add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err();
    assert_eq!(
        error,
        PackError::Install(InstallError::Missing {
            path: RULES_DIR.to_owned()
        })
    );
    let machine = host();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/xudo/rules.d/10-base.toml".to_owned());
    assert!(matches!(
        add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
    let machine = host();
    assert_eq!(
        add_pack(&request(BASE), session(), &machine, &machine).unwrap_err(),
        PackError::Refused(PackRefusal::NotAPack)
    );
    // A rules directory root cannot trust, for either verb.
    let machine = host();
    machine.unreadable.borrow_mut().insert(RULES_DIR.to_owned());
    assert!(matches!(
        add_pack(&request(NGINX), session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
    assert!(matches!(
        remove_pack("nginx-ops", session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
}

#[test]
fn remove_takes_away_only_a_pack_xudo_installed() {
    let machine = host();
    add_pack(&request(NGINX), session(), &machine, &machine).unwrap();
    let report = remove_pack("nginx-ops", session(), &machine, &machine).unwrap();
    assert_eq!(report.path, PATH);
    assert!(report.review.gains.is_empty());
    assert!(report.review.lines()[0].starts_with("codex loses (no password)"));
    assert!(!machine.files.borrow().contains_key(PATH));
    assert!(machine.calls().contains(&format!("remove_managed {PATH}")));

    for name in ["nginx-ops", "../base", "Nginx"] {
        let error = remove_pack(name, session(), &machine, &machine).unwrap_err();
        assert_eq!(error, PackError::NotInstalled(name.to_owned()));
    }
    assert_eq!(
        PackError::NotInstalled("x".to_owned()).to_string(),
        "x is not a pack xudo installed; nothing was changed"
    );
}

#[test]
fn removing_a_pack_other_rules_depend_on_is_refused() {
    let machine = host();
    add_pack(&request(NGINX), session(), &machine, &machine).unwrap();
    // Another file's test pins the pack's action, so without it the test
    // cannot run: the removal would leave a suite that fails.
    let leaning = "[[test]]\nargv = [\"/usr/bin/systemctl\", \"--no-pager\", \"restart\", \"nginx.service\"]\nexpect = \"allow\"\naction = \"pack.nginx.restart\"\n";
    let machine = machine.with_file("/etc/xudo/rules.d/90-tests.toml", leaning);
    let error = remove_pack("nginx-ops", session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Refused(_)), "{error}");
    assert!(machine.files.borrow().contains_key(PATH));

    let machine = host().failing("remove_managed");
    add_pack(&request(NGINX), session(), &machine, &machine).unwrap();
    assert!(matches!(
        remove_pack("nginx-ops", session(), &machine, &machine).unwrap_err(),
        PackError::Install(_)
    ));
}
