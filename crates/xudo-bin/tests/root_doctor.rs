//! `xudo doctor --json` as real root, asking the real `sudo`.
//!
//! `/etc/sudo.conf` can point sudo at another sudoers file, which the hand
//! reader never opens. So a `NOPASSWD` rule there is one only the oracle
//! (`sudo -l -U`) can see. See `xudo-sys/tests/root_lane.rs` for the lane.

#![cfg(feature = "root-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use xudo_tests::root_lane::root_guard;

const XUDO: &str = env!("CARGO_BIN_EXE_xudo");
const SUDO_CONF: &str = "/etc/sudo.conf";
const OTHER: &str = "/etc/xudotest-sudoers";

fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

/// Points sudo at `OTHER` holding `rule`, and puts it all back on drop.
struct Redirected(Option<Vec<u8>>);

impl Redirected {
    fn new(rule: &str) -> Self {
        let saved = fs::read(SUDO_CONF).ok();
        fs::write(OTHER, format!("{rule}\n")).unwrap();
        fs::set_permissions(OTHER, Permissions::from_mode(0o440)).unwrap();
        let conf = "Plugin sudoers_policy sudoers.so sudoers_file=/etc/xudotest-sudoers\n";
        fs::write(SUDO_CONF, conf).unwrap();
        Self(saved)
    }
}

impl Drop for Redirected {
    fn drop(&mut self) {
        let _ = fs::remove_file(OTHER);
        match &self.0 {
            Some(old) => fs::write(SUDO_CONF, old).unwrap(),
            None => fs::remove_file(SUDO_CONF).unwrap(),
        }
    }
}

/// The passwordless-rules check of `xudo doctor --json`, with the xudo group
/// holding `xudotest`.
fn rules_check() -> serde_json::Value {
    let _ = Command::new("/usr/sbin/groupadd")
        .args(["--system", "xudo"])
        .output();
    let added = Command::new("/usr/sbin/usermod")
        .args(["-aG", "xudo", "xudotest"])
        .output()
        .unwrap();
    assert!(added.status.success(), "{added:?}");
    let out = Command::new(XUDO)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = report["paths_to_root"]["checks"].as_array().unwrap();
    checks
        .iter()
        .find(|check| check["check"] == "passwordless_rules")
        .unwrap()
        .clone()
}

#[test]
fn the_real_sudo_reports_a_nopasswd_rule_the_hand_reader_never_opens() {
    if !begin_root_test("the_real_sudo_reports_a_nopasswd_rule_the_hand_reader_never_opens") {
        return;
    }
    let _redirect = Redirected::new("xudotest ALL=(ALL) NOPASSWD: ALL");
    let check = rules_check();
    assert_eq!(check["status"], "found", "{check}");
    let finding = &check["findings"][0];
    assert_eq!(finding["kind"], "backend_listing", "{check}");
    assert_eq!(finding["user"], "xudotest", "{check}");
}

#[test]
fn the_real_sudo_clears_a_user_it_lists_nothing_passwordless_for() {
    if !begin_root_test("the_real_sudo_clears_a_user_it_lists_nothing_passwordless_for") {
        return;
    }
    let _redirect = Redirected::new("xudotest ALL=(ALL) ALL");
    let check = rules_check();
    assert_eq!(check["status"], "clean", "{check}");
    assert_eq!(check["findings"].as_array().unwrap().len(), 0, "{check}");
}
