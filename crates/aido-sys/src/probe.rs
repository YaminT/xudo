//! Answering the backend detector's questions about this machine.
//!
//! The only implementation of [`aido_backend::Probe`] that touches the real
//! filesystem. Deliberately tiny: three questions, no interpretation. All the
//! judgement lives in `aido-backend`, which is pure and therefore testable
//! against a described machine rather than against whatever happens to be
//! installed here.

use std::path::Path;

use aido_backend::Probe;

use crate::exec::{HostRunner, Runner};

/// Probes the machine this process is running on.
#[derive(Clone, Copy, Debug)]
pub struct HostProbe;

impl Probe for HostProbe {
    fn exists(&self, absolute_path: &str) -> bool {
        // Absolute paths only, and the caller supplies constants. Checked
        // anyway, because a relative path here would resolve against a working
        // directory the caller chose.
        Path::new(absolute_path).is_absolute() && Path::new(absolute_path).is_file()
    }

    fn version_banner(&self, absolute_path: &str) -> Option<String> {
        // Both sudo and doas print their banner and exit zero. A failure to run
        // yields `None`, which the detector reads as "assume the stricter
        // implementation" — the safe direction.
        version_banner_with(&HostRunner, absolute_path)
    }

    fn directory_exists(&self, absolute_path: &str) -> bool {
        Path::new(absolute_path).is_absolute() && Path::new(absolute_path).is_dir()
    }

    fn honours_directive(&self, absolute_path: &str, directive: &str) -> bool {
        // A **functional** probe, because the question cannot be answered by
        // reading a version number. `sudo-rs` accepts directives it has not
        // implemented and silently ignores them, so the only evidence that a
        // directive means something is that the backend's own parser accepts a
        // configuration containing it and rejects one containing nonsense.
        //
        // Fed through `/dev/stdin` rather than a temporary file: a predictable
        // path in a world-writable directory is a symlink race, and this way
        // there is no path to race.
        //
        // Any failure to run the probe answers `false`. A directive that cannot
        // be shown to work is treated as absent, so detection reports the
        // backend unusable and aido declines to install rather than advertising
        // a control nobody verified.
        honours_directive_with(&HostRunner, absolute_path, directive)
    }

    fn honours_scoped_directive(&self, absolute_path: &str, directive: &str) -> bool {
        scoped_directive_with(&HostRunner, absolute_path, directive)
    }

    fn validates_named_file(&self, absolute_path: &str) -> bool {
        validates_named_file_with(&HostRunner, absolute_path)
    }

    fn accepts_argument_wildcard(&self, absolute_path: &str) -> bool {
        accepts_wildcard_with(&HostRunner, absolute_path)
    }
}

/// The validator for a sudo-family backend, and how it takes a file.
///
/// `sudo-rs` ships its own `visudo` as `visudo-rs` and spells the flags
/// separately. Keyed on the backend's own path so a host with only one of the
/// two installed is interrogated with the matching validator rather than with
/// whichever one the code assumed.
fn sudo_validator(absolute_path: &str) -> Option<(&'static str, &'static [&'static str])> {
    match absolute_path {
        "/usr/bin/sudo" => Some(("/usr/sbin/visudo", &["-cf", "/dev/stdin"])),
        "/usr/bin/sudo-rs" => Some(("/usr/bin/visudo-rs", &["-c", "-f", "/dev/stdin"])),
        _ => None,
    }
}

/// Whether a sudo-family validator accepts `fragment`.
fn sudo_accepts(runner: &dyn Runner, absolute_path: &str, fragment: &str) -> bool {
    let Some((validator, args)) = sudo_validator(absolute_path) else {
        return false;
    };
    runner
        .run(validator, args, Some(fragment.as_bytes()))
        .is_ok_and(|out| out.success)
}

/// Whether the backend accepts `directive` scoped to one command.
fn scoped_directive_with(runner: &dyn Runner, absolute_path: &str, directive: &str) -> bool {
    let fragment = format!(
        "Cmnd_Alias AIDO_PROBE = /bin/true \"\"\nDefaults!AIDO_PROBE {directive}\n\
         %aido ALL=(root) PASSWD: AIDO_PROBE\n"
    );
    sudo_accepts(runner, absolute_path, &fragment)
}

/// Whether the backend's validator can be pointed at a named file.
///
/// Proved by validating a minimal, valid fragment *through* that interface. A
/// validator that only reads its own hardcoded config cannot answer yes here.
fn validates_named_file_with(runner: &dyn Runner, absolute_path: &str) -> bool {
    if absolute_path == "/usr/bin/doas" {
        // doas takes `-C <file>`, which is a named file by construction.
        return doas_honours(runner, "pty");
    }
    sudo_accepts(
        runner,
        absolute_path,
        "%aido ALL=(root) PASSWD: /bin/true \"\"\n",
    )
}

/// Whether the backend accepts a rule with an argument wildcard.
fn accepts_wildcard_with(runner: &dyn Runner, absolute_path: &str) -> bool {
    sudo_accepts(
        runner,
        absolute_path,
        "%aido ALL=(root) PASSWD: /bin/true *\n",
    )
}

/// Reads a backend's version banner through `runner`.
///
/// `None` when it cannot be run or exits non-zero, which the detector reads as
/// "assume the stricter implementation".
fn version_banner_with(runner: &dyn Runner, absolute_path: &str) -> Option<String> {
    let out = runner.run(absolute_path, &["--version"], None).ok()?;
    if !out.success {
        return None;
    }
    // Some doas ports write the banner to stderr.
    if out.stdout.trim().is_empty() {
        return Some(out.stderr);
    }
    Some(out.stdout)
}

/// Asks the right backend, or refuses.
///
/// Only the two paths aido knows how to interrogate get a probe. Anything else
/// answers `false`, so a caller cannot substitute a cooperative "backend" that
/// agrees to everything.
fn honours_directive_with(runner: &dyn Runner, absolute_path: &str, directive: &str) -> bool {
    match absolute_path {
        "/usr/bin/sudo" | "/usr/bin/sudo-rs" => sudo_honours(runner, absolute_path, directive),
        "/usr/bin/doas" => doas_honours(runner, directive),
        _ => false,
    }
}

/// Whether `sudo`'s own parser accepts a fragment carrying `directive`.
///
/// The fragment is minimal and grants nothing: it names `/bin/true` with no
/// arguments, so even if it were somehow installed it would authorise a no-op.
fn sudo_honours(runner: &dyn Runner, absolute_path: &str, directive: &str) -> bool {
    // The **global** `Defaults` form. Whether the same directive also works
    // scoped to one command is a separate question with a different answer on
    // sudo-rs, and asking both in one fragment is what previously made every
    // sudo-rs probe fail for a reason nobody could see.
    let fragment = format!(
        "Defaults {directive}\nCmnd_Alias AIDO_PROBE = /bin/true \"\"\n\
         %aido ALL=(root) PASSWD: AIDO_PROBE\n"
    );
    sudo_accepts(runner, absolute_path, &fragment)
}

/// Whether `doas`'s own parser accepts a rule carrying `directive`.
///
/// doas has per-rule options rather than a `Defaults` section, so the directive
/// is spliced into the rule itself.
fn doas_honours(runner: &dyn Runner, directive: &str) -> bool {
    // Neither required control maps to a doas keyword: doas has no credential
    // cache unless built --with-timestamp, so the *absence* of `persist` is the
    // control, and every doas allocates a pty for its child. For both, the real
    // question is whether the parser accepts a rule at all, so the option is
    // omitted. Anything else is spliced in verbatim and must parse.
    let option = if matches!(directive, "nopersist" | "pty") {
        String::new()
    } else {
        format!("{directive} ")
    };
    let rule = format!("permit {option}:aido as root cmd /bin/true args\n");
    runner
        .run(
            "/usr/bin/doas",
            &["-C", "/dev/stdin", "/bin/true"],
            Some(rule.as_bytes()),
        )
        .is_ok_and(|out| out.success)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::error::SysError;
    use crate::exec::Output;

    /// A backend described by a table of answers.
    struct FakeRunner {
        /// Exit-zero for these (exe, contains-this-text) pairs.
        accepts: Vec<(&'static str, &'static str)>,
        banner: Option<&'static str>,
        banner_on_stderr: bool,
        fails_to_run: bool,
    }

    impl Default for FakeRunner {
        fn default() -> Self {
            Self {
                accepts: Vec::new(),
                banner: Some("Sudo version 1.9.17p2\n"),
                banner_on_stderr: false,
                fails_to_run: false,
            }
        }
    }

    impl Runner for FakeRunner {
        fn run(
            &self,
            absolute_exe: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<Output, SysError> {
            if self.fails_to_run {
                return Err(SysError::unsupported("fake runner refuses"));
            }
            if args.first() == Some(&"--version") {
                let banner = self.banner.unwrap_or_default().to_owned();
                return Ok(Output {
                    success: self.banner.is_some(),
                    code: Some(i32::from(self.banner.is_none())),
                    stdout: if self.banner_on_stderr {
                        String::new()
                    } else {
                        banner.clone()
                    },
                    stderr: if self.banner_on_stderr {
                        banner
                    } else {
                        String::new()
                    },
                });
            }
            let fed = String::from_utf8_lossy(stdin.unwrap_or_default()).into_owned();
            let accepted = self
                .accepts
                .iter()
                .any(|(exe, needle)| absolute_exe.contains(exe) && fed.contains(needle));
            Ok(Output {
                success: accepted,
                code: Some(i32::from(!accepted)),
                stdout: String::new(),
                stderr: if accepted {
                    String::new()
                } else {
                    "unknown defaults entry".to_owned()
                },
            })
        }
    }

    #[test]
    fn sudo_rs_is_interrogated_with_its_own_validator() {
        // visudo-rs, not visudo, and `-c -f` rather than `-cf`. Asking the wrong
        // validator is asking a binary that is not installed, which answers no
        // to everything and reads as "this backend supports nothing".
        let sudo_rs = FakeRunner {
            accepts: vec![("visudo-rs", "timestamp_timeout=0")],
            ..FakeRunner::default()
        };
        assert!(honours_directive_with(
            &sudo_rs,
            "/usr/bin/sudo-rs",
            "timestamp_timeout=0"
        ));
        // And a runner that knows only the C validator's exact path answers no,
        // so the sudo-rs arm is genuinely asking visudo-rs rather than falling
        // back to whatever validator happens to exist.
        let c_only = FakeRunner {
            accepts: vec![("/usr/sbin/visudo", "timestamp_timeout=0")],
            ..FakeRunner::default()
        };
        assert!(!honours_directive_with(
            &c_only,
            "/usr/bin/sudo-rs",
            "timestamp_timeout=0"
        ));
    }

    #[test]
    fn the_scoped_question_is_asked_separately_from_the_global_one() {
        // sudo-rs 0.2.2 accepts `Defaults timestamp_timeout=0` and rejects
        // `Defaults!ALIAS timestamp_timeout=0`. Asking both in one fragment made
        // every sudo-rs probe fail for a reason nobody could see.
        let global_only = FakeRunner {
            accepts: vec![("visudo-rs", "Defaults timestamp_timeout=0")],
            ..FakeRunner::default()
        };
        assert!(honours_directive_with(
            &global_only,
            "/usr/bin/sudo-rs",
            "timestamp_timeout=0"
        ));
        assert!(!scoped_directive_with(
            &global_only,
            "/usr/bin/sudo-rs",
            "timestamp_timeout=0"
        ));

        let scoped = FakeRunner {
            accepts: vec![("visudo", "Defaults!AIDO_PROBE")],
            ..FakeRunner::default()
        };
        assert!(scoped_directive_with(
            &scoped,
            "/usr/bin/sudo",
            "timestamp_timeout=0"
        ));
    }

    #[test]
    fn the_named_file_and_wildcard_questions_are_asked_of_the_backend() {
        let permissive = FakeRunner {
            accepts: vec![("visudo", "%aido")],
            ..FakeRunner::default()
        };
        assert!(validates_named_file_with(&permissive, "/usr/bin/sudo"));
        assert!(accepts_wildcard_with(&permissive, "/usr/bin/sudo"));

        // A validator that refuses everything answers no to both, which is the
        // fail-closed direction: an unproven capability is absent.
        let strict = FakeRunner::default();
        assert!(!validates_named_file_with(&strict, "/usr/bin/sudo"));
        assert!(!accepts_wildcard_with(&strict, "/usr/bin/sudo"));

        // doas takes `-C <file>`, so a named file is validated by construction.
        let doas = FakeRunner {
            accepts: vec![("doas", "permit")],
            ..FakeRunner::default()
        };
        assert!(validates_named_file_with(&doas, "/usr/bin/doas"));

        // An unknown path is never interrogated at all.
        assert!(!validates_named_file_with(&permissive, "/usr/bin/evil"));
        assert!(!accepts_wildcard_with(&permissive, "/usr/bin/evil"));
        assert!(!scoped_directive_with(&permissive, "/usr/bin/evil", "x"));
    }

    #[test]
    fn a_sudo_directive_is_honoured_only_when_its_own_parser_accepts_it() {
        // The functional probe, exercised without needing a sudo to ask: the
        // fragment goes to the backend's parser and the exit status is the
        // answer.
        let sudo = FakeRunner {
            accepts: vec![("visudo", "timestamp_timeout=0")],
            ..FakeRunner::default()
        };
        assert!(honours_directive_with(
            &sudo,
            "/usr/bin/sudo",
            "timestamp_timeout=0"
        ));
        // The control that makes it meaningful: nonsense is refused.
        assert!(!honours_directive_with(
            &sudo,
            "/usr/bin/sudo",
            "definitely_not_real=1"
        ));
    }

    #[test]
    fn the_probe_fragment_grants_nothing_even_if_it_were_installed() {
        // It names /bin/true with no arguments, so the worst case is a no-op.
        let recorder = FakeRunner {
            accepts: vec![("visudo", "/bin/true \"\"")],
            ..FakeRunner::default()
        };
        assert!(honours_directive_with(
            &recorder,
            "/usr/bin/sudo",
            "use_pty"
        ));
        let no_nopasswd = FakeRunner {
            accepts: vec![("visudo", "NOPASSWD")],
            ..FakeRunner::default()
        };
        assert!(
            !honours_directive_with(&no_nopasswd, "/usr/bin/sudo", "use_pty"),
            "the probe fragment must never contain a passwordless grant"
        );
    }

    #[test]
    fn a_doas_rule_is_probed_with_its_own_syntax() {
        // doas has per-rule options, not a Defaults section.
        let doas = FakeRunner {
            accepts: vec![("doas", "permit :aido as root cmd /bin/true args")],
            ..FakeRunner::default()
        };
        // Neither required control maps to a keyword, so the option is omitted
        // and the question is whether the parser accepts a rule at all.
        assert!(honours_directive_with(&doas, "/usr/bin/doas", "nopersist"));
        assert!(honours_directive_with(&doas, "/usr/bin/doas", "pty"));

        // Anything else is spliced in verbatim and must parse.
        let with_keyword = FakeRunner {
            accepts: vec![("doas", "permit nolog :aido")],
            ..FakeRunner::default()
        };
        assert!(honours_directive_with(
            &with_keyword,
            "/usr/bin/doas",
            "nolog"
        ));
        assert!(!honours_directive_with(
            &with_keyword,
            "/usr/bin/doas",
            "bogus"
        ));
    }

    #[test]
    fn a_runner_that_cannot_start_the_backend_answers_no() {
        // "Cannot run" must read as "not honoured", so detection refuses rather
        // than advertising a control nobody verified.
        let broken = FakeRunner {
            fails_to_run: true,
            ..FakeRunner::default()
        };
        assert!(!honours_directive_with(&broken, "/usr/bin/sudo", "use_pty"));
        assert!(!honours_directive_with(&broken, "/usr/bin/doas", "pty"));
        assert!(version_banner_with(&broken, "/usr/bin/sudo").is_none());
    }

    #[test]
    fn a_banner_on_stderr_is_still_read() {
        // Some doas ports write it there.
        let stderr_banner = FakeRunner {
            banner: Some("doas (OpenDoas) 6.8.2\n"),
            banner_on_stderr: true,
            ..FakeRunner::default()
        };
        assert_eq!(
            version_banner_with(&stderr_banner, "/usr/bin/doas")
                .unwrap()
                .trim(),
            "doas (OpenDoas) 6.8.2"
        );
    }

    #[test]
    fn a_backend_that_exits_non_zero_on_version_yields_no_banner() {
        let mute = FakeRunner {
            banner: None,
            ..FakeRunner::default()
        };
        assert!(version_banner_with(&mute, "/usr/bin/sudo").is_none());
    }

    #[test]
    fn only_the_two_known_backend_paths_are_ever_interrogated() {
        let agreeable = FakeRunner {
            accepts: vec![("", "")],
            ..FakeRunner::default()
        };
        for path in ["/usr/local/bin/sudo", "/tmp/evil-sudo", "/usr/bin/sudo-ish"] {
            assert!(
                !honours_directive_with(&agreeable, path, "use_pty"),
                "{path} was interrogated"
            );
        }
        assert!(honours_directive_with(
            &agreeable,
            "/usr/bin/sudo",
            "use_pty"
        ));
    }

    #[test]
    fn a_real_file_and_directory_are_found() {
        let probe = HostProbe;
        // This crate's own manifest and directory exist on any machine that can
        // run this test.
        assert!(probe.exists(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")));
        assert!(probe.directory_exists(env!("CARGO_MANIFEST_DIR")));
    }

    #[test]
    fn a_missing_path_is_absent_rather_than_an_error() {
        let probe = HostProbe;
        assert!(!probe.exists("/definitely/not/here"));
        assert!(!probe.directory_exists("/definitely/not/here"));
    }

    #[test]
    fn a_directory_is_not_an_executable_and_a_file_is_not_a_directory() {
        let probe = HostProbe;
        assert!(!probe.exists(env!("CARGO_MANIFEST_DIR")));
        assert!(!probe.directory_exists(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")));
    }

    #[test]
    fn a_relative_path_is_refused_rather_than_resolved_against_the_cwd() {
        let probe = HostProbe;
        assert!(!probe.exists("Cargo.toml"));
        assert!(!probe.directory_exists("src"));
    }

    #[test]
    fn the_version_banner_is_read_from_the_backend_itself() {
        // On a host with a real sudo this returns its banner; on one without, it
        // returns None and the detector assumes the stricter implementation.
        let probe = HostProbe;
        // Whatever this machine has, a banner and the executable agree: either
        // both are present or neither is. Asserted without a match arm for a
        // combination that cannot occur.
        assert_eq!(
            probe.version_banner("/usr/bin/sudo").is_some(),
            probe.exists("/usr/bin/sudo")
        );
        assert!(probe.version_banner("/definitely/not/here").is_none());
    }
}
