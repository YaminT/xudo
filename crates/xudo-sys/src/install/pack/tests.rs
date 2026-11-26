#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unnecessary_wraps
)]

use std::collections::BTreeMap;

use xudo_backend::enrol::MANAGED_MARKER;
use xudo_policy::pack::PACK_MARKER;

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

/// A process tree, as `/proc` shows it. Anything not set reads as absent.
#[derive(Clone, Default)]
struct Tree {
    files: BTreeMap<(String, String), Vec<u8>>,
    ns: BTreeMap<String, Vec<u8>>,
}

impl Tree {
    /// `xudo` under `sudo` under a human's shell, all in the human's login
    /// session, under pid 1.
    fn session() -> Self {
        let session = "0::/user.slice/user-1000.slice/session-3.scope\n";
        Self::default()
            .process("self", session, 300)
            .process("300", session, 200)
            .process("200", session, 1)
            .process("1", "0::/init.scope\n", 0)
            .namespace("self", "cgroup:[4026531835]")
            .namespace("1", "cgroup:[4026531835]")
    }

    fn process(self, pid: &str, cgroup: &str, parent: u32) -> Self {
        self.file(pid, "cgroup", cgroup).file(
            pid,
            "status",
            format!("Name:\tx\nPPid:\t{parent}\nUid:\t0\n"),
        )
    }

    fn file(mut self, pid: &str, file: &str, text: impl AsRef<[u8]>) -> Self {
        self.files
            .insert((pid.to_owned(), file.to_owned()), text.as_ref().to_vec());
        self
    }

    fn without(mut self, pid: &str, file: &str) -> Self {
        self.files.remove(&(pid.to_owned(), file.to_owned()));
        self
    }

    fn namespace(mut self, pid: &str, link: &str) -> Self {
        self.ns.insert(pid.to_owned(), link.as_bytes().to_vec());
        self
    }
}

impl Whereabouts for Tree {
    fn read(&self, pid: &str, file: &str) -> std::io::Result<Vec<u8>> {
        self.files
            .get(&(pid.to_owned(), file.to_owned()))
            .cloned()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    fn cgroup_ns(&self, pid: &str) -> std::io::Result<Vec<u8>> {
        self.ns
            .get(pid)
            .cloned()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }
}

fn session() -> Tree {
    Tree::session()
}

fn host() -> Machine {
    Machine::root()
        .with_file("/etc/xudo/rules.d/10-base.toml", BASE)
        .with_file("/etc/xudo/harnesses.d/codex.toml", CODEX)
}

/// The token the operator's own review of adding `text` prints, judged the
/// way `xudo rules add` judges it: the same files, built the same way.
fn operator_token(machine: &Machine, text: &str, allow_waivers: bool) -> String {
    let before = rule_files(machine).unwrap();
    let header = header_of(text.as_bytes()).unwrap();
    let after = with_pack(&before, &header, text.as_bytes());
    let change = Change::Add {
        pack: text.as_bytes(),
        allow_waivers,
    };
    review(before, after, &registry(machine), change)
        .unwrap()
        .token
}

/// The token of removing `name`, as the operator's review prints it.
fn removal_token(machine: &Machine, name: &str) -> String {
    let before = rule_files(machine).unwrap();
    let after = without_pack(&before, name).unwrap();
    review(before, after, &registry(machine), Change::Remove { name })
        .unwrap()
        .token
}

/// What the operator hands root after reviewing `text` on `machine`.
fn request_on(machine: &Machine, text: &str) -> PackRequest {
    PackRequest {
        bytes: text.as_bytes().to_vec(),
        reviewed: operator_token(machine, text, true),
        allow_waivers: true,
    }
}

/// A request with a token that cannot match: for refusals that come first.
fn request(text: &str) -> PackRequest {
    PackRequest {
        bytes: text.as_bytes().to_vec(),
        reviewed: "unreviewed".to_owned(),
        allow_waivers: true,
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
    let report = add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap();
    assert_eq!(report.path, PATH);
    let written = machine.files.borrow()[PATH].clone();
    assert!(written.starts_with(PACK_MARKER), "{written}");
    assert!(written.starts_with(MANAGED_MARKER), "{written}");
    assert!(written.ends_with(NGINX));
    assert_eq!(
        machine.calls(),
        vec![
            format!("lock_dir {RULES_DIR}"),
            format!("write_candidate {PATH}.candidate"),
            format!("install {PATH}"),
        ]
    );
    assert!(report.review.lines()[0].starts_with("codex gains (no password): pack.nginx.restart"));
    // Root's report carries the waiver it installed.
    assert_eq!(report.review.waivers.len(), 1);

    // A new version replaces the file xudo wrote, and says what changed.
    let wider = NGINX.replace("1.0.0", "1.1.0").replace(
        "[\"nginx.service\"]",
        "[\"nginx.service\", \"php.service\"]",
    );
    let report = add_pack(
        &request_on(&machine, &wider),
        &session(),
        &machine,
        &machine,
    )
    .unwrap();
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
    let error = add_pack(&request(&failing), &session(), &machine, &machine).unwrap_err();
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
        let tree = session().file("self", "cgroup", cgroup);
        assert_eq!(
            add_pack(&request(NGINX), &tree, &machine, &machine).unwrap_err(),
            PackError::AgentBox,
            "{cgroup:?}"
        );
        assert_eq!(
            remove_pack("nginx-ops", "x", &tree, &machine, &machine).unwrap_err(),
            PackError::AgentBox
        );
        assert!(machine.calls().is_empty(), "{:?}", machine.calls());
    }
    // A slice that merely starts with the same letters is not the box.
    let machine = host();
    let lookalike = session().file("self", "cgroup", "0::/xudo.slicey/x.scope\n");
    assert!(add_pack(&request_on(&machine, NGINX), &lookalike, &machine, &machine).is_ok());
    assert!(
        PackError::AgentBox
            .to_string()
            .contains("a harness cannot install or remove a rule pack")
    );
}

#[test]
fn a_sudo_that_pam_moved_out_of_the_box_is_caught_by_its_parent() {
    // pam_systemd gives sudo a login session of its own, so `xudo` under it
    // is outside xudo.slice; the agent that ran sudo is not.
    let tree = session()
        .file(
            "self",
            "cgroup",
            "0::/user.slice/user-0.slice/session-c1.scope\n",
        )
        .file(
            "300",
            "cgroup",
            "0::/user.slice/user-0.slice/session-c1.scope\n",
        )
        .file("200", "cgroup", "0::/xudo.slice/xudo-agent@codex.service\n");
    let machine = host();
    assert_eq!(
        add_pack(&request(NGINX), &tree, &machine, &machine).unwrap_err(),
        PackError::AgentBox
    );
    assert!(machine.calls().is_empty());
}

#[test]
fn where_this_runs_cannot_be_told_refuses() {
    let unknown = |tree: Tree| {
        let machine = host();
        let error = add_pack(&request(NGINX), &tree, &machine, &machine).unwrap_err();
        assert!(matches!(error, PackError::CgroupUnknown(_)), "{error}");
        assert!(
            error.to_string().starts_with("cannot tell whether"),
            "{error}"
        );
        assert!(machine.calls().is_empty());
        error.to_string()
    };
    for cgroup in [
        "",
        "garbage\n",
        "0::relative\n",
        // A cgroup namespace's root says nothing about where this is.
        "0::/\n",
    ] {
        unknown(session().file("self", "cgroup", cgroup));
    }
    assert!(unknown(session().without("self", "cgroup")).contains("/proc/self/cgroup"));
    // An ancestor that cannot be read, or that names no parent.
    assert!(unknown(session().without("200", "cgroup")).contains("/proc/200/cgroup"));
    assert!(unknown(session().without("300", "status")).contains("/proc/300/status"));
    assert!(unknown(session().file("200", "status", "Name:\tbash\n")).contains("names no parent"));
    assert!(
        unknown(session().file("200", "status", "PPid:\tnot-a-pid\n")).contains("names no parent")
    );
    assert!(unknown(session().file("200", "status", b"PPid:\t\xff\n")).contains("names no parent"));
    // A chain that never reaches pid 0 is refused, not walked forever.
    assert!(unknown(session().process("200", "0::/user.slice\n", 200)).contains("longer than"));
    // A cgroup namespace other than pid 1's, or one that cannot be read.
    assert!(
        unknown(session().namespace("self", "cgroup:[4026532000]"))
            .contains("namespace of its own")
    );
    let unread = Tree {
        ns: BTreeMap::new(),
        ..session()
    };
    assert!(unknown(unread.clone()).contains("/proc/self/ns/cgroup"));
    assert!(unknown(unread.namespace("self", "cgroup:[1]")).contains("/proc/1/ns/cgroup"));
}

#[test]
fn the_host_reads_proc_and_its_namespace_link() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-tmp")
        .join(format!("whereabouts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("self/ns")).unwrap();
    std::fs::write(dir.join("self/cgroup"), "0::/user.slice\n").unwrap();
    std::os::unix::fs::symlink("cgroup:[4026531835]", dir.join("self/ns/cgroup")).unwrap();
    let at = HostWhereabouts::at(dir.clone());
    assert_eq!(at.read("self", "cgroup").unwrap(), b"0::/user.slice\n");
    assert_eq!(at.cgroup_ns("self").unwrap(), b"cgroup:[4026531835]");
    assert!(at.read("1", "cgroup").is_err());
    assert!(at.cgroup_ns("1").is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    // The machine's own /proc, read through the same code.
    let system = HostWhereabouts::system();
    assert_eq!(system.proc, std::path::PathBuf::from("/proc"));
}

#[test]
fn only_root_installs_or_removes() {
    let mut machine = host();
    machine.uid = 1000;
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert_eq!(error, PackError::NotRoot { uid: 1000 });
    assert_eq!(
        error.to_string(),
        "this needs root (effective uid 1000); nothing was changed"
    );
    assert_eq!(
        remove_pack("nginx-ops", "x", &session(), &machine, &machine).unwrap_err(),
        PackError::NotRoot { uid: 1000 }
    );
}

#[test]
fn the_root_side_re_validates_before_rename() {
    // Changed after the operator's review, even into a pack that still passes.
    let machine = host();
    let mut changed = request_on(&machine, NGINX);
    changed.bytes = NGINX.replace("1.0.0", "1.0.1").into_bytes();
    let error = add_pack(&changed, &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");
    assert!(
        error
            .to_string()
            .contains("not the change that was reviewed"),
        "{error}"
    );
    assert!(wrote_nothing(&machine));

    // The same bytes, but root's rules moved on since the review: an action
    // with the pack's id now exists, so the two cannot load together.
    let clash = NGINX
        .split("[[test]]")
        .next()
        .unwrap()
        .replace("name = \"nginx-ops\"", "name = \"other\"");
    let machine = host().with_file("/etc/xudo/rules.d/20-clash.toml", &clash);
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(
        matches!(error, PackError::Refused(PackRefusal::Load(_))),
        "{error}"
    );
    assert!(wrote_nothing(&machine));

    // The harness left the registry after the review.
    let machine = Machine::root().with_file("/etc/xudo/rules.d/10-base.toml", BASE);
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(error.to_string().contains("not in the registry"), "{error}");
    assert!(wrote_nothing(&machine));

    // A registry root cannot trust is a fault, which refuses.
    let machine = host();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d".to_owned());
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(
        error.to_string().contains("registry failed to load"),
        "{error}"
    );
    let machine = host();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d/codex.toml".to_owned());
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(
        error.to_string().contains("registry failed to load"),
        "{error}"
    );
}

#[test]
fn rules_that_changed_between_review_and_install_refuse() {
    // Reviewed against one rules directory; another rule file, which still
    // loads beside the pack, arrives before the sudo step.
    let machine = host();
    let reviewed = request_on(&machine, NGINX);
    let machine = machine.with_file(
        "/etc/xudo/rules.d/20-more.toml",
        "[[action]]\nid = \"more.uptime\"\ntier = \"diag-read\"\nexe = \"/usr/bin/uptime\"\n",
    );
    let error = add_pack(&reviewed, &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");
    assert!(wrote_nothing(&machine));

    // A harness registered between review and install.
    let machine = host();
    let reviewed = request_on(&machine, NGINX);
    let machine = machine.with_file(
        "/etc/xudo/harnesses.d/claude.toml",
        &CODEX.replace("codex", "claude"),
    );
    let error = add_pack(&reviewed, &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");

    // The flag the review ran with is part of what was reviewed, even for a
    // pack with no waiver in it.
    let ids = "[pack]\nname = \"ids\"\nversion = \"1\"\n\n[[action]]\nid = \"pack.id\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n";
    let machine = host();
    let mut flipped = request_on(&machine, ids);
    flipped.allow_waivers = false;
    let error = add_pack(&flipped, &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");
    flipped.reviewed = operator_token(&machine, ids, false);
    assert!(add_pack(&flipped, &session(), &machine, &machine).is_ok());
}

#[test]
fn a_waiver_needs_the_flag_at_the_sudo_step_too() {
    let machine = host();
    let mut request = request_on(&machine, NGINX);
    request.allow_waivers = false;
    let error = add_pack(&request, &session(), &machine, &machine).unwrap_err();
    assert!(
        matches!(&error, PackError::Refused(PackRefusal::Waivers(found)) if found.len() == 1),
        "{error}"
    );
    assert!(wrote_nothing(&machine));
}

#[test]
fn an_operators_file_is_never_replaced() {
    for text in [NGINX, "# Managed by xudo. Do not edit\n[pack]\n"] {
        let machine = host().with_file(PATH, text);
        let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
        assert!(
            matches!(&error, PackError::Install(InstallError::NotOurs { path, .. }) if path == PATH),
            "{error}"
        );
        assert!(wrote_nothing(&machine));
        assert_eq!(machine.files.borrow()[PATH], text);
        assert_eq!(
            remove_pack("nginx-ops", "x", &session(), &machine, &machine).unwrap_err(),
            PackError::NotInstalled("nginx-ops".to_owned())
        );
    }
}

#[test]
fn a_failed_rename_takes_the_candidate_back() {
    let machine = host().failing("install");
    let error = add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Install(_)), "{error}");
    assert!(
        machine
            .calls()
            .contains(&format!("discard {PATH}.candidate"))
    );
    let machine = host().failing("write_candidate");
    assert!(matches!(
        add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap_err(),
        PackError::Install(_)
    ));
}

#[test]
fn a_busy_rules_directory_refuses_before_anything_is_read() {
    let machine = host().failing("lock_dir");
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Install(_)), "{error}");
    assert_eq!(machine.calls(), vec![format!("lock_dir {RULES_DIR}")]);
    let error = remove_pack("nginx-ops", "x", &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Install(_)), "{error}");
}

#[test]
fn what_cannot_be_read_refuses() {
    let machine = Machine::root();
    let error = add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err();
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
        add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
    let machine = host();
    assert_eq!(
        add_pack(&request(BASE), &session(), &machine, &machine).unwrap_err(),
        PackError::Refused(PackRefusal::NotAPack)
    );
    // A rules directory root cannot trust, for either verb.
    let machine = host();
    machine.unreadable.borrow_mut().insert(RULES_DIR.to_owned());
    assert!(matches!(
        add_pack(&request(NGINX), &session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
    assert!(matches!(
        remove_pack("nginx-ops", "x", &session(), &machine, &machine).unwrap_err(),
        PackError::Install(InstallError::UnsafeFile { .. })
    ));
}

#[test]
fn remove_takes_away_only_a_pack_xudo_installed_and_only_as_reviewed() {
    let machine = host();
    add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap();
    // A token from another state of the rules is refused.
    let stale = removal_token(&machine, "nginx-ops");
    let moved = machine.with_file(
        "/etc/xudo/rules.d/20-more.toml",
        "[[action]]\nid = \"more.uptime\"\ntier = \"diag-read\"\nexe = \"/usr/bin/uptime\"\n",
    );
    let error = remove_pack("nginx-ops", &stale, &session(), &moved, &moved).unwrap_err();
    assert!(matches!(error, PackError::Changed { .. }), "{error}");
    assert!(moved.files.borrow().contains_key(PATH));

    let token = removal_token(&moved, "nginx-ops");
    let report = remove_pack("nginx-ops", &token, &session(), &moved, &moved).unwrap();
    assert_eq!(report.path, PATH);
    assert!(report.review.gains.is_empty());
    assert!(report.review.lines()[0].starts_with("codex loses (no password)"));
    assert!(!moved.files.borrow().contains_key(PATH));
    assert!(moved.calls().contains(&format!("remove_managed {PATH}")));

    for name in ["nginx-ops", "../base", "Nginx"] {
        let error = remove_pack(name, &token, &session(), &moved, &moved).unwrap_err();
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
    add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap();
    // Another file's test pins the pack's action, so without it the test
    // cannot run: the removal would leave a suite that fails.
    let leaning = "[[test]]\nargv = [\"/usr/bin/systemctl\", \"--no-pager\", \"restart\", \"nginx.service\"]\nexpect = \"allow\"\naction = \"pack.nginx.restart\"\n";
    let machine = machine.with_file("/etc/xudo/rules.d/90-tests.toml", leaning);
    let error = remove_pack("nginx-ops", "x", &session(), &machine, &machine).unwrap_err();
    assert!(matches!(error, PackError::Refused(_)), "{error}");
    assert!(machine.files.borrow().contains_key(PATH));

    let machine = host().failing("remove_managed");
    add_pack(&request_on(&machine, NGINX), &session(), &machine, &machine).unwrap();
    let token = removal_token(&machine, "nginx-ops");
    assert!(matches!(
        remove_pack("nginx-ops", &token, &session(), &machine, &machine).unwrap_err(),
        PackError::Install(_)
    ));
}
