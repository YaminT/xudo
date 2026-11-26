#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;

use xudo_backend::InstallPlan;
use xudo_backend::enrol::{AccountScan, EnrolPlan, EnrolRequest, PlannedFile};
use xudo_sys::{AgentError, AgentRow, InstallError, InstallReport, PackReport};

use super::*;

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

const IDS: &str = "[pack]\nname = \"ids\"\nversion = \"2\"\n\n[[action]]\nid = \"pack.id\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n";

const CODEX: &str = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";

/// An `/etc/xudo` of its own under `target/`, never `/tmp`.
struct Etc {
    root: PathBuf,
}

impl Drop for Etc {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Etc {
    fn new(name: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("packs-{name}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(root.join("rules.d")).unwrap();
        std::fs::create_dir_all(root.join("harnesses.d")).unwrap();
        std::fs::write(root.join("harnesses.d/codex.toml"), CODEX).unwrap();
        Self { root }
    }

    fn rules(&self) -> PathBuf {
        self.root.join("rules.d")
    }

    fn write(&self, name: &str, text: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// An installer that answers the pack calls as told and refuses the rest.
#[derive(Default)]
struct Script {
    asked: RefCell<Vec<String>>,
    answer: RefCell<Option<Result<PackReport, PackError>>>,
}

impl Script {
    fn answering(answer: Result<PackReport, PackError>) -> Self {
        Self {
            asked: RefCell::default(),
            answer: RefCell::new(Some(answer)),
        }
    }

    fn take(&self) -> Result<PackReport, PackError> {
        self.answer
            .borrow_mut()
            .take()
            .unwrap_or(Err(InstallError::NoInstaller.into()))
    }
}

impl Installer for Script {
    fn run(&self, _plan: &InstallPlan) -> Result<InstallReport, InstallError> {
        Err(InstallError::NoInstaller)
    }

    fn agent_plan(&self, _: &EnrolRequest, _: AccountScan) -> Result<EnrolPlan, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_apply(&self, _plan: &EnrolPlan) -> Result<(), AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_list(&self) -> Result<Vec<AgentRow>, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_remove(&self, _label: &str) -> Result<Vec<String>, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn pack_add(&self, request: &PackRequest) -> Result<PackReport, PackError> {
        self.asked.borrow_mut().push(format!(
            "add {} {}",
            request.reviewed,
            String::from_utf8(request.bytes.clone()).unwrap()
        ));
        self.take()
    }

    fn pack_remove(&self, name: &str) -> Result<PackReport, PackError> {
        self.asked.borrow_mut().push(format!("remove {name}"));
        self.take()
    }
}

fn go(etc: &Etc, installer: &Script, action: &RulesAction) -> (ExitCode, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&etc.rules(), installer, action, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn add(file: PathBuf) -> RulesAction {
    RulesAction::Add {
        file,
        reviewed: None,
    }
}

#[test]
fn the_double_refuses_everything_but_packs() {
    let script = Script::default();
    let plan = xudo_backend::uninstall_plan(xudo_backend::BackendKind::Sudo);
    assert!(script.run(&plan).is_err());
    let request = EnrolRequest {
        label: "a".to_owned(),
        account: "b".to_owned(),
        reviewers: vec![],
        argv: vec![],
    };
    let scan = AccountScan {
        uid: 1,
        blockers: vec![],
        doas: false,
    };
    assert!(script.agent_plan(&request, scan).is_err());
    let file = || PlannedFile {
        path: "/x".to_owned(),
        contents: String::new(),
        mode: 0o644,
        keep: false,
    };
    let enrol = EnrolPlan {
        label: "a".to_owned(),
        account: "b".to_owned(),
        unit: "u".to_owned(),
        registry: file(),
        drop_in_dir: "/d".to_owned(),
        drop_in: file(),
        env: file(),
        memberships: Vec::new(),
    };
    assert!(script.agent_apply(&enrol).is_err());
    assert!(script.agent_list().is_err());
    assert!(script.agent_remove("a").is_err());
    assert!(script.pack_remove("a").is_err());
}

#[test]
fn a_review_shows_every_new_capability_and_installs_nothing() {
    let etc = Etc::new("preview");
    let file = etc.write("nginx.toml", NGINX.as_bytes());
    let script = Script::default();
    let (code, out, err) = go(&etc, &script, &add(file.clone()));
    assert_eq!(code, ExitCode::Delegated, "{err}");
    assert!(out.starts_with("pack nginx-ops 1.0.0 for codex\n"), "{out}");
    assert!(
        out.contains(
            "  codex gains (no password): pack.nginx.restart: /usr/bin/systemctl --no-pager restart"
        ),
        "{out}"
    );
    assert!(
        out.contains("  password path gains (password): pack.nginx.restart"),
        "{out}"
    );
    let hash = digest(NGINX.as_bytes());
    assert!(
        out.contains(&format!(
            "sudo xudo rules add --reviewed {hash} {}",
            file.display()
        )),
        "{out}"
    );
    assert!(script.asked.borrow().is_empty());
    assert_eq!(std::fs::read_dir(etc.rules()).unwrap().count(), 0);
}

#[test]
fn a_pack_for_no_harness_and_one_already_installed_say_so() {
    let etc = Etc::new("same");
    let file = etc.write("ids.toml", IDS.as_bytes());
    std::fs::write(
        etc.rules().join("pack-ids.toml"),
        installed_bytes(IDS.as_bytes()),
    )
    .unwrap();
    let (code, out, _) = go(&etc, &Script::default(), &add(file));
    assert_eq!(code, ExitCode::Delegated);
    assert!(
        out.starts_with("pack ids 2 for no harness\nno caller gains or loses anything\n"),
        "{out}"
    );
}

#[test]
fn a_pack_with_a_failing_test_is_never_offered_for_install() {
    let etc = Etc::new("failing");
    let failing = format!(
        "{NGINX}\n[[test]]\nargv = [\"/usr/bin/systemctl\", \"--no-pager\", \"restart\", \"php.service\"]\nexpect = \"allow\"\n"
    );
    let file = etc.write("bad.toml", failing.as_bytes());
    let (code, out, err) = go(&etc, &Script::default(), &add(file));
    assert_eq!(code, ExitCode::LintError);
    assert_eq!(out, "");
    assert!(
        err.starts_with("xudo: the pack is refused; nothing was installed:\n  the [[test]]"),
        "{err}"
    );
}

#[test]
fn what_is_not_a_reviewable_pack_is_refused() {
    let etc = Etc::new("refusals");
    let script = Script::default();
    // Not there.
    let (code, _, err) = go(&etc, &script, &add(etc.root.join("absent.toml")));
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.contains("cannot read"), "{err}");
    // Too big to be one.
    let huge = etc.write("huge.toml", &vec![b'#'; MAX_PACK_BYTES + 1]);
    let (code, _, err) = go(&etc, &script, &add(huge));
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.contains("larger than"), "{err}");
    // A rule file without a header.
    let plain = etc.write(
        "plain.toml",
        b"[[action]]\nid = \"x\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n",
    );
    let (code, _, err) = go(&etc, &script, &add(plain));
    assert_eq!(code, ExitCode::LintError);
    assert!(err.contains("no [pack] header"), "{err}");
    // Installed rules that do not load.
    let pack = etc.write("ids.toml", IDS.as_bytes());
    std::fs::write(etc.rules().join("10-broken.toml"), "[[action]]\n").unwrap();
    let (code, _, err) = go(&etc, &script, &add(pack.clone()));
    assert_eq!(code, ExitCode::LintError);
    assert!(err.contains("the installed rules do not load"), "{err}");
    // No rules directory at all.
    std::fs::remove_dir_all(etc.rules()).unwrap();
    let (code, _, err) = go(&etc, &script, &add(pack));
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.contains("cannot read the rules directory"), "{err}");
    assert!(script.asked.borrow().is_empty());
}

fn report(path: &str) -> PackReport {
    let review = xudo_policy::pack::review(
        vec![],
        vec![RuleFile {
            name: b"pack-ids.toml".to_vec(),
            bytes: IDS.as_bytes().to_vec(),
        }],
        &Ok(vec![]),
    )
    .unwrap();
    PackReport {
        path: path.to_owned(),
        review,
    }
}

#[test]
fn reviewed_hands_root_the_bytes_and_the_digest() {
    let etc = Etc::new("reviewed");
    let file = etc.write("ids.toml", IDS.as_bytes());
    let reviewed = |file: &Path| RulesAction::Add {
        file: file.to_path_buf(),
        reviewed: Some("abc".to_owned()),
    };
    let script = Script::answering(Ok(report("/etc/xudo/rules.d/pack-ids.toml")));
    let (code, out, _) = go(&etc, &script, &reviewed(&file));
    assert_eq!(code, ExitCode::Delegated);
    assert!(
        out.ends_with("installed /etc/xudo/rules.d/pack-ids.toml\n"),
        "{out}"
    );
    assert!(
        out.starts_with("  password path gains (password): pack.id: /usr/bin/id\n"),
        "{out}"
    );
    assert_eq!(script.asked.borrow()[0], format!("add abc {IDS}"));

    // Root's refusals come back with their reasons.
    let problems = Script::answering(Err(PackError::Refused(PackRefusal::Problems(vec![
        "no near miss".to_owned(),
    ]))));
    let (code, _, err) = go(&etc, &problems, &reviewed(&file));
    assert_eq!(code, ExitCode::LintError);
    assert!(err.contains("  no near miss"), "{err}");
    let other = Script::answering(Err(PackError::Refused(PackRefusal::NotAPack)));
    assert_eq!(go(&etc, &other, &reviewed(&file)).0, ExitCode::LintError);
    let changed = Script::answering(Err(PackError::AgentBox));
    let (code, _, err) = go(&etc, &changed, &reviewed(&file));
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.contains("agent's box"), "{err}");

    // A file that cannot be read never reaches root.
    let unread = Script::default();
    let (code, _, _) = go(&etc, &unread, &reviewed(&etc.root.join("absent")));
    assert_eq!(code, ExitCode::Unusable);
    assert!(unread.asked.borrow().is_empty());
}

#[test]
fn remove_reports_what_root_did() {
    let etc = Etc::new("remove");
    let action = RulesAction::Remove {
        name: "ids".to_owned(),
    };
    let script = Script::answering(Ok(report("/etc/xudo/rules.d/pack-ids.toml")));
    let (code, out, _) = go(&etc, &script, &action);
    assert_eq!(code, ExitCode::Delegated);
    assert!(
        out.ends_with("removed /etc/xudo/rules.d/pack-ids.toml\n"),
        "{out}"
    );
    assert_eq!(script.asked.borrow()[0], "remove ids");
    let (code, _, err) = go(&etc, &Script::default(), &action);
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.contains("cannot modify the machine"), "{err}");
}

#[test]
fn list_names_each_pack_and_who_wrote_it() {
    let etc = Etc::new("list");
    let (code, out, _) = go(&etc, &Script::default(), &RulesAction::List);
    assert_eq!(
        (code, out.as_str()),
        (ExitCode::Delegated, "No rule packs.\n")
    );
    std::fs::write(
        etc.rules().join("pack-ids.toml"),
        installed_bytes(IDS.as_bytes()),
    )
    .unwrap();
    std::fs::write(etc.rules().join("50-nginx.toml"), NGINX).unwrap();
    let (code, out, _) = go(&etc, &Script::default(), &RulesAction::List);
    assert_eq!(code, ExitCode::Delegated);
    assert_eq!(
        out,
        "nginx-ops 1.0.0 for=codex 50-nginx.toml (written by hand; xudo rules remove leaves it)\n\
         ids 2 for=- pack-ids.toml (installed by xudo rules add)\n"
    );
    std::fs::write(etc.rules().join("10-broken.toml"), "[[action]]\n").unwrap();
    let (code, _, err) = go(&etc, &Script::default(), &RulesAction::List);
    assert_eq!(code, ExitCode::Unusable);
    assert!(err.starts_with("xudo: "), "{err}");
}
