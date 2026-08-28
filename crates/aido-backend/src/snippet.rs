//! Generating the one file that grants `aido` its privilege.
//!
//! Every constraint here is historically earned. Read the module docs on the
//! crate root before changing any of it.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::detect::{Backend, BackendKind};

/// Where the sudo drop-in goes.
///
/// **No dot beyond the absence of an extension, and no trailing tilde.** `sudo`
/// silently ignores files in `sudoers.d` whose names contain a dot or end in
/// `~`, so `/etc/sudoers.d/aido.conf` installs cleanly and grants nothing.
pub const SUDOERS_PATH: &str = "/etc/sudoers.d/aido";

/// Where the doas drop-in goes, on ports that have one.
pub const DOAS_DROP_IN_PATH: &str = "/etc/doas.d/60-aido.conf";

/// The shared doas config, appended to when there is no drop-in directory.
pub const DOAS_CONF_PATH: &str = "/etc/doas.conf";

/// Opens aido's block in a shared file, so uninstall can remove exactly it.
pub const DOAS_BEGIN: &str = "### aido:begin — do not edit between the markers";
/// Closes aido's block.
pub const DOAS_END: &str = "### aido:end";

/// The unix group whose members may invoke the gate.
pub const AIDO_GROUP: &str = "aido";

/// The human-path helper: always requires a password.
pub const GATE_AUTH: &str = "/usr/libexec/aido/aido-gate-auth";

/// The agent-path helper: passwordless.
///
/// **Not installed by the beta.** Until enrollment, the broker, and out-of-band
/// confirmation exist, a passwordless rule is a standing root grant with no
/// compensating control. [`SudoersSnippet::human_only`] is the only constructor
/// the current release uses, and it does not mention this path at all — the
/// file is absent from the package rather than present and unreferenced.
pub const GATE_NOPASS: &str = "/usr/libexec/aido/aido-gate-nopass";

/// The `secure_path` given to the privileged child.
const SECURE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Why a snippet could not be generated.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnippetError {
    /// The backend cannot honour a control aido depends on.
    #[error("cannot generate a snippet for {backend}: {reason}")]
    Unsupported {
        /// Which backend.
        backend: String,
        /// What it cannot do.
        reason: String,
    },
}

/// A generated sudoers drop-in, and how to check it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoersSnippet {
    /// The file's contents.
    pub contents: String,
    /// Whether a passwordless rule is included.
    ///
    /// `false` for every build that ships today.
    pub includes_nopass: bool,
    /// The argv that validates this snippet, or `None` when the backend cannot
    /// validate a named file and the caller must validate by substitution.
    pub validate_argv: Option<Vec<String>>,
}

impl SudoersSnippet {
    /// The absolute path this snippet installs to.
    ///
    /// A function rather than a caller-supplied argument, so no caller can pass
    /// a name that `sudo` would silently ignore.
    pub fn path() -> &'static str {
        SUDOERS_PATH
    }

    /// The file mode. `0440`: readable by root and the group, writable by
    /// nobody.
    pub fn mode() -> u32 {
        0o440
    }

    /// Generates the human-only snippet: every invocation prompts.
    ///
    /// This is what ships. There is no passwordless rule and no reference to the
    /// agent-path helper.
    ///
    /// # Errors
    ///
    /// Returns [`SnippetError::Unsupported`] if the backend cannot disable its
    /// credential cache or allocate a pty, because a snippet without those two
    /// promises less than aido claims.
    pub fn human_only(backend: &Backend) -> Result<Self, SnippetError> {
        Self::generate(backend, false)
    }

    /// Generates a snippet that also grants the passwordless agent path.
    ///
    /// Not reachable from the current CLI. It exists so the shape can be
    /// reviewed and tested now, and so the diff that enables it is small and
    /// obvious rather than sprawling.
    ///
    /// # Errors
    ///
    /// As [`Self::human_only`].
    pub fn with_agent_path(backend: &Backend) -> Result<Self, SnippetError> {
        Self::generate(backend, true)
    }

    fn generate(backend: &Backend, includes_nopass: bool) -> Result<Self, SnippetError> {
        if matches!(backend.kind, BackendKind::Doas) {
            return Err(SnippetError::Unsupported {
                backend: backend.kind.label().to_owned(),
                reason: "doas does not use sudoers syntax; use DoasSnippet".to_owned(),
            });
        }
        if let Some(capability) = backend.capabilities.missing_required().first() {
            return Err(SnippetError::Unsupported {
                backend: backend.kind.label().to_owned(),
                reason: capability.rationale().to_owned(),
            });
        }

        let mut out = String::new();
        out.push_str(&header(backend));

        // `""` after the path means "with no arguments at all". This is the
        // single most important token in the file: it removes sudo's fnmatch
        // layer from the trust path entirely, so the whole sudoers
        // argument-injection class becomes unreachable rather than guarded
        // against.
        let _ = writeln!(out, "Cmnd_Alias AIDO_AUTH = {GATE_AUTH} \"\"");
        if includes_nopass {
            let _ = writeln!(out, "Cmnd_Alias AIDO_NOPASS = {GATE_NOPASS} \"\"");
        }
        out.push('\n');

        out.push_str(&defaults_line("AIDO_AUTH"));
        if includes_nopass {
            out.push_str(&defaults_line("AIDO_NOPASS"));
        }
        out.push('\n');

        let _ = writeln!(out, "%{AIDO_GROUP} ALL=(root) PASSWD:   AIDO_AUTH");
        if includes_nopass {
            let _ = writeln!(out, "%{AIDO_GROUP} ALL=(root) NOPASSWD: AIDO_NOPASS");
        }

        Ok(Self {
            contents: out,
            includes_nopass,
            validate_argv: validate_argv(backend),
        })
    }
}

/// The explanatory header. An operator who opens this file mid-incident should
/// not have to guess what it is or why each directive is there.
fn header(backend: &Backend) -> String {
    format!(
        "# Managed by aido. Do not edit; run `aido doctor --fix` instead.\n\
         #\n\
         # Backend at install time: {kind} ({version})\n\
         #\n\
         # Every line below is load-bearing:\n\
         #   \"\"                    the helper may be run with NO arguments at all.\n\
         #                         This removes sudo's argument-glob matching from the\n\
         #                         trust path, so argument injection is unreachable\n\
         #                         rather than guarded against.\n\
         #   timestamp_timeout=0   no credential cache. Without this, one path can ride\n\
         #                         a credential cached by an earlier unrelated sudo.\n\
         #   use_pty               a fresh pty for the child; the only fix for terminal\n\
         #                         injection (TIOCSTI/TIOCLINUX).\n\
         #   env_reset, !setenv    the child environment is rebuilt, and the caller\n\
         #                         cannot inject one on the command line.\n\
         #   secure_path           the caller's PATH never influences resolution.\n\
         #\n\
         # The helper takes no arguments and reads nothing from its environment. It is\n\
         # safe to invoke directly, because it is itself the policy engine.\n\
         \n",
        kind = backend.kind.label(),
        version = backend.version,
    )
}

/// The `Defaults` line for one command alias.
fn defaults_line(alias: &str) -> String {
    format!(
        "Defaults!{alias} env_reset, !setenv, secure_path=\"{SECURE_PATH}\", \
         timestamp_timeout=0, use_pty, !visiblepw\n"
    )
}

/// How to validate a snippet on this backend, if it can be done in place.
fn validate_argv(backend: &Backend) -> Option<Vec<String>> {
    if !backend.capabilities.has(Capability::ValidateNamedFile) {
        // sudo-rs's visudo validates only /etc/sudoers. The caller must
        // validate by substitution into a temporary copy instead, which is
        // reported as `None` rather than as a command that would silently check
        // the wrong file.
        return None;
    }
    Some(vec![
        "/usr/sbin/visudo".to_owned(),
        "-cf".to_owned(),
        // The temporary file, not the destination: validate before installing,
        // never after.
        "{candidate}".to_owned(),
    ])
}

/// A generated doas configuration, and how to check it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoasSnippet {
    /// The block's contents, including its sentinels when appended.
    pub contents: String,
    /// Where it goes.
    pub path: String,
    /// Whether it is a whole file (a drop-in) or a block appended to a shared
    /// file.
    pub is_drop_in: bool,
    /// The argv that validates it.
    pub validate_argv: Vec<String>,
}

impl DoasSnippet {
    /// Generates the human-only doas configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SnippetError::Unsupported`] for a non-doas backend, or when a
    /// required capability is missing.
    pub fn human_only(backend: &Backend) -> Result<Self, SnippetError> {
        if !matches!(backend.kind, BackendKind::Doas) {
            return Err(SnippetError::Unsupported {
                backend: backend.kind.label().to_owned(),
                reason: "not a doas backend; use SudoersSnippet".to_owned(),
            });
        }
        if let Some(capability) = backend.capabilities.missing_required().first() {
            return Err(SnippetError::Unsupported {
                backend: backend.kind.label().to_owned(),
                reason: capability.rationale().to_owned(),
            });
        }

        let is_drop_in = backend.capabilities.has(Capability::DropInDirectory);

        // `args` with nothing after it means "with exactly no arguments", which
        // is doas's equivalent of sudo's `""`. Note that omitting `args`
        // entirely would mean "any arguments" — the inverse — which is why it is
        // written explicitly.
        let rule = format!("permit persist :{AIDO_GROUP} as root cmd {GATE_AUTH} args\n");

        let body = format!(
            "# Managed by aido. Do not edit between the markers.\n\
             #\n\
             # Backend at install time: {kind} ({version})\n\
             #\n\
             # `args` with nothing after it means the helper may be run with exactly no\n\
             # arguments. Omitting `args` would mean ANY arguments, which is the inverse\n\
             # of what is wanted, so it is written explicitly.\n\
             #\n\
             # aido does not rely on `persist`: `OpenDoas` disables it unless built\n\
             # --with-timestamp, so every invocation is assumed to prompt.\n\
             {rule}",
            kind = backend.kind.label(),
            version = backend.version,
        );

        let (contents, path) = if is_drop_in {
            (body, DOAS_DROP_IN_PATH.to_owned())
        } else {
            (
                format!("{DOAS_BEGIN}\n{body}{DOAS_END}\n"),
                DOAS_CONF_PATH.to_owned(),
            )
        };

        Ok(Self {
            contents,
            path,
            is_drop_in,
            validate_argv: vec![
                "/usr/bin/doas".to_owned(),
                "-C".to_owned(),
                "{candidate}".to_owned(),
                GATE_AUTH.to_owned(),
            ],
        })
    }

    /// The file mode. `0400` for a file doas reads: root-only.
    pub fn mode() -> u32 {
        0o400
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::capability::CapabilityMatrix;

    fn sudo() -> Backend {
        Backend {
            kind: BackendKind::Sudo,
            version: "Sudo version 1.9.17p2".to_owned(),
            capabilities: CapabilityMatrix::from_supported([
                Capability::DisableCredentialCache,
                Capability::AllocatePty,
                Capability::PerCommandDefaults,
                Capability::DropInDirectory,
                Capability::ValidateNamedFile,
            ]),
        }
    }

    fn sudo_rs() -> Backend {
        Backend {
            kind: BackendKind::SudoRs,
            version: "sudo-rs 0.2.8".to_owned(),
            capabilities: CapabilityMatrix::from_supported([
                Capability::DisableCredentialCache,
                Capability::AllocatePty,
                Capability::PerCommandDefaults,
                Capability::DropInDirectory,
                Capability::RejectsArgumentWildcards,
            ]),
        }
    }

    fn doas(drop_in: bool) -> Backend {
        let mut caps = CapabilityMatrix::from_supported([
            Capability::DisableCredentialCache,
            Capability::AllocatePty,
            Capability::ValidateNamedFile,
        ]);
        if drop_in {
            caps = caps.with(Capability::DropInDirectory);
        }
        Backend {
            kind: BackendKind::Doas,
            version: "doas (OpenDoas) 6.8.2".to_owned(),
            capabilities: caps,
        }
    }

    #[test]
    fn the_install_path_can_never_be_a_name_sudo_would_ignore() {
        // sudo silently ignores a drop-in whose name contains a dot or ends in
        // `~`. The path is a constant precisely so no caller can supply one.
        let path = SudoersSnippet::path();
        let name = path.rsplit('/').next().unwrap();
        assert!(!name.contains('.'), "{name} contains a dot");
        assert!(!name.ends_with('~'), "{name} ends in a tilde");
        assert_eq!(path, "/etc/sudoers.d/aido");
        assert_eq!(SudoersSnippet::mode(), 0o440);
    }

    #[test]
    fn the_shipped_snippet_grants_only_the_password_path() {
        // The headline property of the beta: there is no passwordless rule, and
        // the agent helper is not even named.
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        assert!(!snippet.includes_nopass);
        assert!(!snippet.contents.contains("NOPASSWD"));
        assert!(
            !snippet.contents.contains(GATE_NOPASS),
            "the agent helper must not be referenced at all"
        );
        assert!(snippet.contents.contains("PASSWD:   AIDO_AUTH"));
    }

    #[test]
    fn the_command_is_granted_with_zero_arguments() {
        // The single most important token in the file.
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        assert!(
            snippet
                .contents
                .contains(&format!("Cmnd_Alias AIDO_AUTH = {GATE_AUTH} \"\"")),
            "{}",
            snippet.contents
        );
    }

    #[test]
    fn every_load_bearing_default_is_present() {
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        for directive in [
            "env_reset",
            "!setenv",
            "timestamp_timeout=0",
            "use_pty",
            "!visiblepw",
            "secure_path=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
        ] {
            assert!(
                snippet.contents.contains(directive),
                "missing {directive} in:\n{}",
                snippet.contents
            );
        }
    }

    #[test]
    fn the_defaults_are_scoped_to_aidos_own_commands() {
        // `Defaults!ALIAS`, not a bare `Defaults`: aido's settings must not leak
        // onto an operator's unrelated rules.
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        assert!(snippet.contents.contains("Defaults!AIDO_AUTH "));
        assert!(
            !snippet
                .contents
                .lines()
                .any(|l| l.starts_with("Defaults ") || l.starts_with("Defaults\t")),
            "an unscoped Defaults line would affect unrelated commands"
        );
    }

    #[test]
    fn the_header_explains_each_directive_to_whoever_opens_the_file() {
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        assert!(snippet.contents.starts_with("# Managed by aido."));
        assert!(snippet.contents.contains("Sudo version 1.9.17p2"));
        for explained in ["timestamp_timeout=0", "use_pty", "secure_path"] {
            assert!(
                snippet
                    .contents
                    .lines()
                    .filter(|l| l.starts_with('#'))
                    .any(|l| l.contains(explained)),
                "{explained} is used but not explained"
            );
        }
    }

    #[test]
    fn sudo_can_validate_the_candidate_file_before_it_is_installed() {
        let snippet = SudoersSnippet::human_only(&sudo()).unwrap();
        let argv = snippet.validate_argv.unwrap();
        assert_eq!(argv[0], "/usr/sbin/visudo");
        assert_eq!(argv[1], "-cf");
        // The candidate, never the destination: validate before installing.
        assert_eq!(argv[2], "{candidate}");
        assert!(!argv.iter().any(|a| a == SUDOERS_PATH));
    }

    #[test]
    fn sudo_rs_reports_no_validation_command_rather_than_a_misleading_one() {
        // sudo-rs's visudo validates only /etc/sudoers. Emitting the same
        // command would silently check a different file and report success.
        let snippet = SudoersSnippet::human_only(&sudo_rs()).unwrap();
        assert!(snippet.validate_argv.is_none());
        // The snippet itself is still generated and still correct.
        assert!(snippet.contents.contains("timestamp_timeout=0"));
    }

    #[test]
    fn the_agent_path_snippet_adds_exactly_one_passwordless_rule() {
        // Reviewable now so the diff that enables it later is small.
        let snippet = SudoersSnippet::with_agent_path(&sudo()).unwrap();
        assert!(snippet.includes_nopass);
        assert_eq!(
            snippet
                .contents
                .lines()
                .filter(|l| l.contains("NOPASSWD"))
                .count(),
            1
        );
        // And NOPASSWD attaches only to the agent alias, never the human one.
        let nopass_line = snippet
            .contents
            .lines()
            .find(|l| l.contains("NOPASSWD"))
            .unwrap();
        assert!(nopass_line.contains("AIDO_NOPASS"));
        assert!(!nopass_line.contains("AIDO_AUTH"));
        // Both helpers keep the same hardening. Counted over directive lines
        // only, because the explanatory header mentions the directive too.
        assert_eq!(
            snippet
                .contents
                .lines()
                .filter(|l| l.starts_with("Defaults!") && l.contains("timestamp_timeout=0"))
                .count(),
            2
        );
    }

    #[test]
    fn a_backend_missing_a_required_control_gets_no_snippet_at_all() {
        let crippled = Backend {
            kind: BackendKind::Sudo,
            version: "Sudo version 0.0".to_owned(),
            capabilities: CapabilityMatrix::from_supported([Capability::AllocatePty]),
        };
        let err = SudoersSnippet::human_only(&crippled).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot generate a snippet for sudo")
        );
        assert!(err.to_string().contains("REQUIRED"), "{err}");
    }

    #[test]
    fn a_doas_backend_is_refused_by_the_sudoers_generator() {
        let err = SudoersSnippet::human_only(&doas(false)).unwrap_err();
        assert!(
            err.to_string().contains("does not use sudoers syntax"),
            "{err}"
        );
        assert!(err.to_string().contains("DoasSnippet"), "{err}");
    }

    #[test]
    fn a_doas_port_without_a_drop_in_gets_a_removable_delimited_block() {
        // The block must be removable exactly, or uninstall damages an
        // operator's own doas.conf.
        let snippet = DoasSnippet::human_only(&doas(false)).unwrap();
        assert!(!snippet.is_drop_in);
        assert_eq!(snippet.path, DOAS_CONF_PATH);
        assert!(snippet.contents.starts_with(DOAS_BEGIN));
        assert!(snippet.contents.trim_end().ends_with(DOAS_END));
        assert_eq!(DoasSnippet::mode(), 0o400);
    }

    #[test]
    fn a_doas_port_with_a_drop_in_gets_its_own_file_and_no_sentinels() {
        let snippet = DoasSnippet::human_only(&doas(true)).unwrap();
        assert!(snippet.is_drop_in);
        assert_eq!(snippet.path, DOAS_DROP_IN_PATH);
        assert!(!snippet.contents.contains(DOAS_BEGIN));
    }

    #[test]
    fn the_doas_rule_permits_exactly_zero_arguments() {
        // `args` with nothing after it. Omitting it would mean ANY arguments,
        // which is the inverse, so the generated rule states it explicitly.
        let snippet = DoasSnippet::human_only(&doas(true)).unwrap();
        let rule = snippet
            .contents
            .lines()
            .find(|l| l.starts_with("permit"))
            .unwrap();
        assert!(rule.ends_with(" args"), "{rule}");
        assert!(rule.contains(&format!("cmd {GATE_AUTH}")), "{rule}");
        assert!(rule.contains(&format!(":{AIDO_GROUP}")), "{rule}");
        assert!(!rule.contains(GATE_NOPASS));
    }

    #[test]
    fn the_doas_validation_command_checks_the_candidate() {
        let snippet = DoasSnippet::human_only(&doas(true)).unwrap();
        assert_eq!(snippet.validate_argv[0], "/usr/bin/doas");
        assert_eq!(snippet.validate_argv[1], "-C");
        assert_eq!(snippet.validate_argv[2], "{candidate}");
    }

    #[test]
    fn a_sudo_backend_is_refused_by_the_doas_generator() {
        let err = DoasSnippet::human_only(&sudo()).unwrap_err();
        assert!(err.to_string().contains("not a doas backend"), "{err}");
    }

    #[test]
    fn a_crippled_doas_backend_gets_no_snippet() {
        let crippled = Backend {
            kind: BackendKind::Doas,
            version: "doas 0.0".to_owned(),
            capabilities: CapabilityMatrix::empty(),
        };
        let err = DoasSnippet::human_only(&crippled).unwrap_err();
        assert!(err.to_string().contains("REQUIRED"), "{err}");
    }

    #[test]
    fn snippets_round_trip_for_the_audit_record() {
        let sudoers = SudoersSnippet::human_only(&sudo()).unwrap();
        let json = serde_json::to_string(&sudoers).unwrap();
        assert_eq!(
            serde_json::from_str::<SudoersSnippet>(&json).unwrap(),
            sudoers
        );
        assert!(format!("{sudoers:?}").contains("includes_nopass"));

        let doas_snippet = DoasSnippet::human_only(&doas(true)).unwrap();
        let json = serde_json::to_string(&doas_snippet).unwrap();
        assert_eq!(
            serde_json::from_str::<DoasSnippet>(&json).unwrap(),
            doas_snippet
        );
        assert!(format!("{doas_snippet:?}").contains("is_drop_in"));
    }
}
