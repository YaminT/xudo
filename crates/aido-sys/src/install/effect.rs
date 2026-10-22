//! Whether the backend would honour the rule that was just written.
//!
//! A file in `/etc/sudoers.d` proves nothing: `sudo` skips a name with a dot in
//! it and `sudo-rs` ignores directives it does not support. So after an install
//! the question is put to the backend itself, which is the only thing that
//! knows: `sudo -l -U <user>` lists what that user may run, and the gate is
//! either in the list or it is not.
//!
//! **This is not the functional probe, and it is never reported as success.**
//! It shows the rule is read; it does not show the gate runs as uid 0, which
//! needs a request minted through the broker (plan item C1). It prints on a
//! line of its own, beside the `NOT VERIFIED` that the missing probe produces.
//!
//! The group the rule grants to starts empty, by design (membership is the
//! privilege grant). With no member there is no one to ask about, and that is
//! reported as it is — unchecked — rather than inferred either way. `doas` has
//! no question that takes a group or a user, so it is unchecked too.

use aido_backend::BackendKind;
use aido_backend::snippet::{AIDO_GROUP, GATE_AUTH};

use crate::exec::Runner;

/// What the backend said about the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The backend lists the gate among what `user` may run.
    InEffect {
        /// The account that was asked about.
        user: String,
    },
    /// The backend does not list the gate for `user`: the file is there and
    /// does nothing.
    NotInEffect {
        /// The account that was asked about.
        user: String,
    },
    /// The question could not be put.
    Unchecked {
        /// Why not.
        reason: String,
    },
}

impl Effect {
    /// One line for the operator. Never says "verified".
    pub fn describe(&self) -> String {
        match self {
            Self::InEffect { user } => format!(
                "the backend lists {GATE_AUTH} for {user}: the rule is read. This is not the \
                 functional probe; it does not show the gate runs as root"
            ),
            Self::NotInEffect { user } => format!(
                "WARNING: the backend does not list {GATE_AUTH} for {user}, a member of \
                 {AIDO_GROUP}: the file is installed and the rule is NOT in effect"
            ),
            Self::Unchecked { reason } => {
                format!("the rule was not checked for being in effect: {reason}")
            }
        }
    }
}

/// Asks the backend, through `runner`, whether the gate is granted.
pub fn check_effect(runner: &dyn Runner, backend: BackendKind) -> Effect {
    let unchecked = |reason: &str| Effect::Unchecked {
        reason: reason.to_owned(),
    };
    if !matches!(backend, BackendKind::Sudo | BackendKind::SudoRs) {
        return unchecked("doas has no question that names a user, so it cannot be asked");
    }
    let Ok(group) = runner.run("/usr/bin/getent", &["group", AIDO_GROUP], None) else {
        return unchecked("the group could not be looked up");
    };
    let Some(user) = first_member(&group.stdout) else {
        return unchecked(
            "no account is in the aido group yet, so there is no one to ask the backend about",
        );
    };
    let Ok(listing) = runner.run(backend.exe(), &["-l", "-U", &user], None) else {
        return unchecked("the backend could not be asked");
    };
    // The refusal ("is not allowed to run") goes to either stream and exits
    // non-zero, so both are read and the status is not.
    if format!("{}{}", listing.stdout, listing.stderr).contains(GATE_AUTH) {
        Effect::InEffect { user }
    } else {
        Effect::NotInEffect { user }
    }
}

/// The first member of a `getent group` line, if it is a name safe to pass as
/// an argument: it cannot be read as an option, and it is one word.
fn first_member(line: &str) -> Option<String> {
    // Both iterators always yield one item, so there is no `None` to handle:
    // an empty one is an empty name, which is refused below.
    let members = line.trim().rsplit(':').next().unwrap_or_default();
    let name = members.split(',').next().unwrap_or_default();
    let safe = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    safe.then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::error::SysError;
    use crate::exec::Output;

    /// Answers each call from a script, and records what was run.
    struct Script {
        answers: RefCell<Vec<Result<Output, SysError>>>,
        ran: RefCell<Vec<String>>,
    }

    impl Script {
        fn new(answers: Vec<Result<Output, SysError>>) -> Self {
            Self {
                answers: RefCell::new(answers.into_iter().rev().collect()),
                ran: RefCell::new(Vec::new()),
            }
        }
    }

    impl Runner for Script {
        fn run(&self, exe: &str, args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, SysError> {
            self.ran
                .borrow_mut()
                .push(format!("{exe} {}", args.join(" ")));
            self.answers.borrow_mut().pop().unwrap_or_else(broken)
        }
    }

    // Beside `broken`, in the one type a script's answers have.
    #[allow(clippy::unnecessary_wraps)]
    fn said(stdout: &str, stderr: &str) -> Result<Output, SysError> {
        Ok(Output {
            success: true,
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        })
    }

    /// Whether the check said it could not check, by what it says to the
    /// operator (a `matches!` in measured test code leaves a false arm that
    /// never runs).
    fn is_unchecked(runner: &Script, backend: BackendKind) -> bool {
        check_effect(runner, backend)
            .describe()
            .contains("was not checked")
    }

    fn broken() -> Result<Output, SysError> {
        Err(SysError::Unsupported {
            operation: "a program the script has no answer for".to_owned(),
        })
    }

    #[test]
    fn a_listed_gate_is_in_effect() {
        let runner = Script::new(vec![
            said("aido:x:998:alice,bob\n", ""),
            said(
                &format!("User alice may run:\n    (root) PASSWD: {GATE_AUTH} \"\"\n"),
                "",
            ),
        ]);
        assert_eq!(
            check_effect(&runner, BackendKind::Sudo),
            Effect::InEffect {
                user: "alice".to_owned()
            }
        );
        assert_eq!(
            *runner.ran.borrow(),
            ["/usr/bin/getent group aido", "/usr/bin/sudo -l -U alice"]
        );
    }

    #[test]
    fn a_gate_the_backend_does_not_list_is_not_in_effect() {
        let runner = Script::new(vec![
            said("aido:x:998:alice\n", ""),
            said("", "User alice is not allowed to run sudo on host.\n"),
        ]);
        let effect = check_effect(&runner, BackendKind::SudoRs);
        assert_eq!(
            effect,
            Effect::NotInEffect {
                user: "alice".to_owned()
            }
        );
        assert!(effect.describe().contains("NOT in effect"));
    }

    #[test]
    fn an_empty_group_is_unchecked_rather_than_assumed() {
        let runner = Script::new(vec![said("aido:x:998:\n", "")]);
        assert!(is_unchecked(&runner, BackendKind::Sudo));
        assert_eq!(runner.ran.borrow().len(), 1, "sudo was asked about no one");
    }

    #[test]
    fn a_group_that_is_not_there_is_unchecked() {
        let runner = Script::new(vec![said("", "")]);
        assert!(is_unchecked(&runner, BackendKind::Sudo));
    }

    #[test]
    fn a_lookup_that_fails_is_unchecked() {
        let runner = Script::new(vec![broken()]);
        assert!(is_unchecked(&runner, BackendKind::Sudo));
    }

    #[test]
    fn a_backend_that_cannot_be_run_is_unchecked() {
        let runner = Script::new(vec![said("aido:x:998:alice\n", ""), broken()]);
        assert!(is_unchecked(&runner, BackendKind::Sudo));
    }

    #[test]
    fn doas_is_unchecked_and_nothing_is_run() {
        let runner = Script::new(vec![]);
        assert!(is_unchecked(&runner, BackendKind::Doas));
        assert!(runner.ran.borrow().is_empty());
    }

    #[test]
    fn a_member_name_that_could_be_an_option_is_never_passed_to_the_backend() {
        for line in [
            "aido:x:998:-U\n",
            "aido:x:998:--help,alice\n",
            "aido:x:998:al ice\n",
            "aido:x:998:al\u{e9}\n",
        ] {
            let runner = Script::new(vec![said(line, "")]);
            assert!(is_unchecked(&runner, BackendKind::Sudo), "{line:?}");
            assert_eq!(runner.ran.borrow().len(), 1, "{line:?} reached the backend");
        }
    }

    #[test]
    fn nothing_here_ever_reads_as_success() {
        let all = [
            Effect::InEffect {
                user: "a".to_owned(),
            },
            Effect::NotInEffect {
                user: "a".to_owned(),
            },
            Effect::Unchecked {
                reason: "r".to_owned(),
            },
        ];
        for effect in all {
            let text = effect.describe().to_lowercase();
            assert!(!text.contains("verified"), "{text}");
        }
    }
}
