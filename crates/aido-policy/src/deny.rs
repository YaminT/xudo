//! The compiled-in deny-list.
//!
//! # Why this is compiled in
//!
//! An allowlist is only as good as its worst entry, and the worst entry is
//! always the one nobody reviewed. This list is therefore part of the binary:
//! it is evaluated *after* allow matching, it cannot be edited, shadowed,
//! disabled, or reordered by any configuration file, and a shipped copy under
//! `/etc/aido/deny.d/` exists for operators to read, not for the engine to
//! load.
//!
//! # Why it enumerates capabilities, not binaries
//!
//! Denying `/bin/sh` by name is defeated by a copy, a hardlink, a bind mount,
//! or a `busybox` multicall applet. So each entry here names a *capability* —
//! "spawns a shell", "executes a program named in its own configuration",
//! "writes a caller-chosen path" — and the binary list is merely the current
//! evidence for that capability. When a new binary turns out to have the
//! capability, it joins an existing class rather than starting a new one.
//!
//! # This is defence in depth, not the boundary
//!
//! The boundary is a small set of narrow named actions. This list is what
//! catches the mistake in one of them. A design that relies on the deny-list
//! being complete has already lost, because the space of programs that can be
//! turned into a root shell is not enumerable — see `GTFOBins`, and the CI gate
//! that checks every allowlisted binary against it.
//!
//! # Scope of the current list
//!
//! This is the seed set covering the classes with a known exploitation path.
//! It is smaller than the full inventory in the design plan and is expanded by
//! adding cases to [`CapabilityClass`], never by loosening a matcher. Nothing
//! about the list is silently capped: [`deny_list_version`] changes whenever it
//! does, and the version is written into every audit record.

use bstr::ByteSlice;
use serde::{Deserialize, Serialize};

use crate::argv::Argv;

/// Version of the compiled-in list, recorded in every audit record.
///
/// Bump on every change, so a decision can be replayed against the exact list
/// that produced it.
pub fn deny_list_version() -> u32 {
    1
}

/// A class of capability that is never permitted as root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    /// Runs an interactive or scripted shell.
    SpawnsShell,
    /// Executes caller-supplied source in a general-purpose language.
    Interpreter,
    /// Runs an arbitrary program named in its own arguments.
    ExecProxy,
    /// Enters or creates a namespace, or changes the process's privilege set.
    PrivilegeTool,
    /// Reads a caller-chosen path, or executes through a pager or search tool.
    ArbitraryRead,
    /// Writes a caller-chosen path.
    ///
    /// The most under-estimated class. Arbitrary root write *is* root code
    /// execution: `/etc/ld.so.preload`, `/etc/cron.d`, `/etc/sudoers.d`, and
    /// `/root/.ssh/authorized_keys` each suffice on their own.
    ArbitraryWrite,
    /// Executes a program named in a configuration value or hook.
    ConfigNamedProgram,
    /// Writes any file that decides what is permitted, including aido's own.
    SelfModification,
    /// Writes a block device or creates a filesystem.
    DeviceOrFilesystem,
    /// Changes users, groups, or credentials.
    CredentialTool,
    /// Loads or unloads kernel code.
    KernelModule,
    /// Changes the machine's power or boot state.
    PowerState,
    /// Creates or rewrites a unit definition, rather than acting on one.
    UnitDefinitionMutation,
    /// Talks to a container daemon that can mount the host filesystem.
    ContainerRuntime,
    /// Disables audit, `SELinux`, or `AppArmor`.
    SecuritySubsystem,
    /// Installs from a local file, URL, or VCS reference rather than a
    /// configured repository.
    UntrustedPackageSource,
    /// Schedules future execution.
    Scheduler,
}

impl CapabilityClass {
    /// Why this class is denied, for the operator and the audit record.
    pub fn rationale(self) -> &'static str {
        match self {
            Self::SpawnsShell => {
                "a shell as uid 0 is the terminal state of every privilege escalation; \
                 there is nothing left to constrain"
            }
            Self::Interpreter => {
                "an interpreter executes caller-supplied source, so authorising one \
                 authorises everything it can be told to do"
            }
            Self::ExecProxy => {
                "the program runs another program named in its arguments, so the argv \
                 constraint applies to the wrong command"
            }
            Self::PrivilegeTool => {
                "namespace and privilege tools change the meaning of every subsequent \
                 check, including aido's own"
            }
            Self::ArbitraryRead => {
                "pagers and search tools execute helpers and honour environment hooks, \
                 and a caller-chosen read path reaches every secret on the host"
            }
            Self::ArbitraryWrite => {
                "an arbitrary root write is root code execution: ld.so.preload, cron.d, \
                 sudoers.d, and authorized_keys each suffice on their own"
            }
            Self::ConfigNamedProgram => {
                "a configuration value or hook that names a program is a shell injection \
                 that never appears in argv as a command"
            }
            Self::SelfModification => {
                "writing the thing that decides removes the policy; this is the highest \
                 priority class in the list"
            }
            Self::DeviceOrFilesystem => {
                "a raw device write or a new filesystem destroys data irrecoverably and \
                 can rewrite the running system"
            }
            Self::CredentialTool => {
                "creating or changing a credential is a permanent, independent path to \
                 root that outlives aido"
            }
            Self::KernelModule => {
                "loaded kernel code is above every userspace control, aido included"
            }
            Self::PowerState => {
                "a reboot or power-off is an availability decision a human makes, and it \
                 destroys the session that would have caught a mistake"
            }
            Self::UnitDefinitionMutation => {
                "writing a unit definition schedules future root execution, which is a \
                 different act from starting a service that already exists"
            }
            Self::ContainerRuntime => {
                "a container runtime can mount the host root and rewrite anything on it, \
                 so there is no safe subset of its arguments"
            }
            Self::SecuritySubsystem => {
                "disabling audit or a mandatory access control system removes the \
                 evidence and the backstop at once"
            }
            Self::UntrustedPackageSource => {
                "a local file, URL, or VCS reference runs maintainer scripts as root \
                 from a source no repository signed"
            }
            Self::Scheduler => {
                "a scheduled job is root execution at a time when nobody is watching"
            }
        }
    }
}

/// A matched deny-list entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyFinding {
    /// The capability class that matched.
    pub class: CapabilityClass,
    /// What specifically triggered it, for the audit record.
    pub evidence: String,
}

impl DenyFinding {
    fn new(class: CapabilityClass, evidence: impl Into<String>) -> Self {
        Self {
            class,
            evidence: evidence.into(),
        }
    }
}

/// Executables that are, or can become, a shell.
const SHELLS: &[&[u8]] = &[
    b"sh", b"bash", b"dash", b"zsh", b"ksh", b"csh", b"tcsh", b"fish", b"ash", b"rbash", b"busybox",
];

/// General-purpose interpreters.
const INTERPRETERS: &[&[u8]] = &[
    b"python", b"python2", b"python3", b"perl", b"ruby", b"node", b"lua", b"luajit", b"php",
    b"awk", b"gawk", b"mawk", b"tclsh", b"expect", b"Rscript", b"deno", b"bun",
];

/// Programs whose whole purpose is to execute another program.
const EXEC_PROXIES: &[&[u8]] = &[
    b"env",
    b"nice",
    b"nohup",
    b"timeout",
    b"setsid",
    b"stdbuf",
    b"ionice",
    b"taskset",
    b"chrt",
    b"setarch",
    b"xargs",
    b"parallel",
    b"watch",
    b"flock",
    b"script",
];

/// Namespace and privilege manipulation.
const PRIVILEGE_TOOLS: &[&[u8]] = &[
    b"unshare",
    b"nsenter",
    b"chroot",
    b"systemd-run",
    b"systemd-nspawn",
    b"machinectl",
    b"setpriv",
    b"capsh",
    b"setcap",
    b"sudo",
    b"doas",
    b"su",
    b"pkexec",
    b"run0",
];

/// Readers that execute helpers, honour hooks, or take an arbitrary path.
const ARBITRARY_READERS: &[&[u8]] = &[
    b"less",
    b"more",
    b"most",
    b"man",
    b"pager",
    b"bat",
    b"w3m",
    b"lynx",
    b"pinfo",
    b"find",
    b"gdb",
    b"strace",
    b"ltrace",
    b"perf",
    b"bpftrace",
    b"bpftool",
    b"valgrind",
    b"lldb",
];

/// Generic write primitives. Each is equivalent to full root.
const ARBITRARY_WRITERS: &[&[u8]] = &[
    b"tee",
    b"dd",
    b"cp",
    b"mv",
    b"install",
    b"ln",
    b"truncate",
    b"split",
    b"shred",
    b"rsync",
    b"tar",
    b"zip",
    b"unzip",
    b"7z",
    b"cpio",
    b"vi",
    b"vim",
    b"nvim",
    b"nano",
    b"emacs",
    b"ed",
    b"ex",
    b"joe",
    b"mcedit",
    b"sed",
    b"git",
    b"ssh",
    b"scp",
    b"sftp",
    b"socat",
    b"nc",
    b"ncat",
    b"telnet",
    b"ftp",
    b"curl",
    b"wget",
];

/// Filesystem and block-device tools.
const DEVICE_TOOLS: &[&[u8]] = &[
    b"mkfs",
    b"mke2fs",
    b"mkswap",
    b"wipefs",
    b"blkdiscard",
    b"badblocks",
    b"fdisk",
    b"sfdisk",
    b"cfdisk",
    b"gdisk",
    b"sgdisk",
    b"parted",
    b"partprobe",
    b"cryptsetup",
    b"lvremove",
    b"vgremove",
    b"pvremove",
];

/// User, group, and credential tools.
const CREDENTIAL_TOOLS: &[&[u8]] = &[
    b"passwd",
    b"chpasswd",
    b"useradd",
    b"userdel",
    b"usermod",
    b"groupadd",
    b"groupdel",
    b"groupmod",
    b"gpasswd",
    b"newusers",
    b"vipw",
    b"vigr",
    b"visudo",
    b"chage",
    b"chsh",
    b"chfn",
];

/// Kernel module tools.
const KERNEL_MODULE_TOOLS: &[&[u8]] = &[
    b"insmod",
    b"rmmod",
    b"modprobe",
    b"kmod",
    b"depmod",
    b"kexec",
];

/// Power-state tools.
const POWER_TOOLS: &[&[u8]] = &[
    b"shutdown",
    b"reboot",
    b"halt",
    b"poweroff",
    b"telinit",
    b"init",
    b"kexec-reboot",
];

/// Container runtimes and daemons.
const CONTAINER_TOOLS: &[&[u8]] = &[
    b"docker",
    b"dockerd",
    b"podman",
    b"containerd",
    b"ctr",
    b"nerdctl",
    b"lxc",
    b"lxc-attach",
    b"runc",
    b"crictl",
];

/// Audit and mandatory-access-control tools.
const SECURITY_TOOLS: &[&[u8]] = &[
    b"auditctl",
    b"augenrules",
    b"setenforce",
    b"semanage",
    b"setsebool",
    b"aa-complain",
    b"aa-disable",
    b"apparmor_parser",
];

/// Schedulers.
const SCHEDULERS: &[&[u8]] = &[
    b"crontab",
    b"at",
    b"batch",
    b"anacron",
    b"run-parts",
    b"systemd-tmpfiles",
    b"logrotate",
];

/// Paths whose contents decide what is permitted.
///
/// Ordered longest-prefix-irrelevant: a match on any of these is fatal, so the
/// order is only for readability.
const PROTECTED_PREFIXES: &[&[u8]] = &[
    b"/etc/aido",
    b"/usr/libexec/aido",
    b"/var/log/aido",
    b"/var/lib/aido",
    b"/run/aido",
    b"/etc/sudoers",
    b"/etc/sudoers.d",
    b"/etc/doas.conf",
    b"/etc/doas.d",
    b"/etc/polkit-1",
    b"/usr/share/polkit-1",
    b"/etc/pam.d",
    b"/etc/security",
    b"/etc/nsswitch.conf",
    b"/etc/ld.so.preload",
    b"/etc/ld.so.conf",
    b"/etc/ld.so.conf.d",
    b"/etc/shadow",
    b"/etc/gshadow",
    b"/etc/passwd",
    b"/etc/group",
    b"/etc/environment",
    b"/etc/profile",
    b"/etc/profile.d",
    b"/etc/bash.bashrc",
    b"/etc/systemd/system",
    b"/usr/lib/systemd/system",
    b"/etc/cron.d",
    b"/etc/crontab",
    b"/etc/cron.hourly",
    b"/etc/cron.daily",
    b"/etc/cron.weekly",
    b"/etc/cron.monthly",
    b"/var/spool/cron",
    b"/etc/apt/sources.list",
    b"/etc/apt/sources.list.d",
    b"/etc/apt/apt.conf",
    b"/etc/apt/apt.conf.d",
    b"/etc/apt/preferences",
    b"/etc/apt/trusted.gpg",
    b"/etc/yum.repos.d",
    b"/etc/pacman.conf",
    b"/etc/pacman.d",
    b"/usr/share/keyrings",
    b"/etc/selinux",
    b"/etc/apparmor.d",
    b"/root/.ssh",
    b"/etc/ssh",
    b"/etc/modules",
    b"/etc/modules-load.d",
    b"/etc/sysctl.conf",
    b"/etc/default",
];

/// `sysctl` keys whose value grants code execution or removes a control.
const FATAL_SYSCTL_KEYS: &[&[u8]] = &[
    b"kernel.core_pattern",
    b"kernel.modprobe",
    b"kernel.modules_disabled",
    b"kernel.sysrq",
    b"kernel.ftrace_enabled",
    b"kernel.kexec_load_disabled",
    b"kernel.unprivileged_bpf_disabled",
    b"kernel.unprivileged_userns_clone",
    b"kernel.yama.ptrace_scope",
    b"kernel.perf_event_paranoid",
    b"fs.protected_symlinks",
    b"fs.protected_hardlinks",
    b"fs.suid_dumpable",
];

/// `systemctl` verbs that write or reinterpret a unit definition.
const UNIT_MUTATING_VERBS: &[&[u8]] = &[
    b"enable",
    b"disable",
    b"mask",
    b"unmask",
    b"link",
    b"revert",
    b"edit",
    b"set-property",
    b"set-environment",
    b"unset-environment",
    b"import-environment",
    b"preset",
    b"preset-all",
    b"add-wants",
    b"add-requires",
    b"set-default",
    b"switch-root",
];

/// Extracts the final path component of an executable path.
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit_str(b"/").next().unwrap_or(path)
}

/// Returns `true` when `name` is in `set`, ignoring a trailing version suffix.
///
/// `python3.11` is `python`, and `mkfs.ext4` is `mkfs`. Matching the stem is
/// what stops a version bump from silently un-denying an interpreter.
fn matches_name(name: &[u8], set: &[&[u8]]) -> bool {
    let stem = name.split_str(b".").next().unwrap_or(name);
    set.iter().any(|candidate| {
        *candidate == name || *candidate == stem || {
            // python3, python3.11 -> python
            name.strip_suffix(b"3") == Some(*candidate)
                || name.strip_suffix(b"2") == Some(*candidate)
        }
    })
}

/// Returns `true` when `path` is at or beneath any protected prefix.
fn touches_protected_path(path: &[u8]) -> bool {
    if !path.starts_with(b"/") {
        return false;
    }
    PROTECTED_PREFIXES.iter().any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.starts_with(b"/"))
    })
}

/// Evaluates the compiled-in deny-list against a resolved executable and its
/// canonical argv.
///
/// `exe` must already be the absolute, resolved path; this crate cannot resolve
/// it. `argv` must already be canonicalized, so `--key=value` has been split
/// and a flag cannot hide its payload behind an `=`.
///
/// Returns every class that matched, sorted and deduplicated, so an audit
/// record names all of them rather than whichever happened to be checked first.
pub fn evaluate_deny_list(exe: &[u8], argv: &Argv) -> Vec<DenyFinding> {
    let name = basename(exe);
    let mut findings = deny_by_executable(name);
    findings.extend(deny_by_arguments(name, argv));

    findings.sort_by(|a, b| (a.class, a.evidence.as_str()).cmp(&(b.class, b.evidence.as_str())));
    findings.dedup();
    findings
}

/// Classes implied by the executable's identity alone.
fn deny_by_executable(name: &[u8]) -> Vec<DenyFinding> {
    let mut findings: Vec<DenyFinding> = Vec::new();
    let by_name: &[(&[&[u8]], CapabilityClass)] = &[
        (SHELLS, CapabilityClass::SpawnsShell),
        (INTERPRETERS, CapabilityClass::Interpreter),
        (EXEC_PROXIES, CapabilityClass::ExecProxy),
        (PRIVILEGE_TOOLS, CapabilityClass::PrivilegeTool),
        (ARBITRARY_READERS, CapabilityClass::ArbitraryRead),
        (ARBITRARY_WRITERS, CapabilityClass::ArbitraryWrite),
        (DEVICE_TOOLS, CapabilityClass::DeviceOrFilesystem),
        (CREDENTIAL_TOOLS, CapabilityClass::CredentialTool),
        (KERNEL_MODULE_TOOLS, CapabilityClass::KernelModule),
        (POWER_TOOLS, CapabilityClass::PowerState),
        (CONTAINER_TOOLS, CapabilityClass::ContainerRuntime),
        (SECURITY_TOOLS, CapabilityClass::SecuritySubsystem),
        (SCHEDULERS, CapabilityClass::Scheduler),
    ];
    for (set, class) in by_name {
        if matches_name(name, set) {
            findings.push(DenyFinding::new(
                *class,
                format!("executable {}", name.as_bstr()),
            ));
        }
    }
    findings
}

/// Classes implied by the shape of the arguments.
///
/// `name` is consulted only where a flag's meaning depends on which program
/// receives it: `-p` is fatal to `sysctl` and harmless to `systemctl`.
fn deny_by_arguments(name: &[u8], argv: &Argv) -> Vec<DenyFinding> {
    let mut findings: Vec<DenyFinding> = Vec::new();
    for (index, arg) in argv.as_slice().iter().enumerate() {
        let bytes = arg.as_bytes();

        // A configuration assignment whose value is a program. `apt-get -o
        // DPkg::Pre-Invoke::='sh -c ...'` is a root shell reached through a
        // rule that only meant to install a package, and the word `sh` never
        // appears as a command in argv.
        if bytes.contains_str("Pre-Invoke")
            || bytes.contains_str("Post-Invoke")
            || bytes.contains_str("core.pager")
            || bytes.contains_str("core.sshCommand")
            || bytes.contains_str("core.editor")
            || bytes.contains_str("ProxyCommand")
            || bytes.contains_str("LocalCommand")
            || bytes.contains_str("--to-command")
            || bytes.contains_str("checkpoint-action")
            || bytes.contains_str("use-compress-program")
            || bytes.contains_str("--rsh")
        {
            findings.push(DenyFinding::new(
                CapabilityClass::ConfigNamedProgram,
                format!("argument {index} names a program in a configuration value"),
            ));
        }

        // Any argument naming a protected path, regardless of the executable.
        if touches_protected_path(bytes) {
            findings.push(DenyFinding::new(
                CapabilityClass::SelfModification,
                format!(
                    "argument {index} names the protected path {}",
                    bytes.as_bstr()
                ),
            ));
        }

        // A raw device target.
        if bytes.starts_with(b"/dev/") || bytes.starts_with(b"of=/dev/") {
            findings.push(DenyFinding::new(
                CapabilityClass::DeviceOrFilesystem,
                format!("argument {index} names the device {}", bytes.as_bstr()),
            ));
        }

        // A local artefact, URL, or VCS reference as a package source.
        if bytes.contains_str("://")
            || bytes.ends_with(b".deb")
            || bytes.ends_with(b".rpm")
            || bytes.ends_with(b".apk")
            || bytes.ends_with(b".whl")
            || bytes.ends_with(b".tar.gz")
            || bytes.starts_with(b"git+")
        {
            findings.push(DenyFinding::new(
                CapabilityClass::UntrustedPackageSource,
                format!(
                    "argument {index} names an unsigned source {}",
                    bytes.as_bstr()
                ),
            ));
        }

        // A fatal sysctl key, in either `-w key=value` or bare form.
        let key = bytes.split_str(b"=").next().unwrap_or(bytes);
        if FATAL_SYSCTL_KEYS.contains(&key) {
            findings.push(DenyFinding::new(
                CapabilityClass::SelfModification,
                format!("argument {index} writes the sysctl key {}", key.as_bstr()),
            ));
        }

        // File-driven sysctl application: the values come from a file this
        // argv does not name, so argv matching cannot see them.
        if name == b"sysctl" && matches!(bytes, b"-p" | b"--load" | b"--system") {
            findings.push(DenyFinding::new(
                CapabilityClass::ConfigNamedProgram,
                format!("argument {index} applies sysctl values from a file"),
            ));
        }

        // A unit-definition-mutating verb.
        if name == b"systemctl" && UNIT_MUTATING_VERBS.contains(&bytes) {
            findings.push(DenyFinding::new(
                CapabilityClass::UnitDefinitionMutation,
                format!(
                    "argument {index} is the unit-mutating verb {}",
                    bytes.as_bstr()
                ),
            ));
        }

        // An option that redirects a package manager's configuration, hooks, or
        // root, independent of which manager it is.
        if matches!(bytes, b"-o" | b"--option" | b"-c" | b"--config-file")
            && matches!(
                name,
                b"apt" | b"apt-get" | b"dpkg" | b"dnf" | b"yum" | b"zypper" | b"pacman"
            )
        {
            findings.push(DenyFinding::new(
                CapabilityClass::ConfigNamedProgram,
                format!("argument {index} redirects package-manager configuration"),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn classes(exe: &str, args: &[&str]) -> Vec<CapabilityClass> {
        let findings = evaluate_deny_list(exe.as_bytes(), &Argv::new(args.to_vec()));
        let mut c: Vec<CapabilityClass> = findings.into_iter().map(|f| f.class).collect();
        c.sort_unstable();
        c.dedup();
        c
    }

    fn denies(exe: &str, args: &[&str]) -> bool {
        !evaluate_deny_list(exe.as_bytes(), &Argv::new(args.to_vec())).is_empty()
    }

    #[test]
    fn version_is_reported_for_replay() {
        assert_eq!(deny_list_version(), 1);
    }

    #[test]
    fn a_clean_allowlisted_command_is_not_denied() {
        assert!(!denies("/usr/bin/systemctl", &["restart", "nginx.service"]));
        assert!(!denies("/usr/bin/apt-get", &["install", "--", "ripgrep"]));
        assert!(!denies(
            "/usr/bin/journalctl",
            &["--no-pager", "-u", "nginx.service"]
        ));
    }

    #[test]
    fn shells_are_denied_however_they_are_spelled() {
        for exe in [
            "/bin/sh",
            "/bin/bash",
            "/usr/local/bin/zsh",
            "/opt/weird/path/dash",
        ] {
            assert!(denies(exe, &[]), "{exe} was permitted");
        }
    }

    #[test]
    fn busybox_is_denied_because_it_is_a_multicall_shell() {
        // Name-based denial of /bin/sh is defeated by busybox; busybox is
        // therefore in the shell class itself.
        assert!(classes("/bin/busybox", &["sh"]).contains(&CapabilityClass::SpawnsShell));
    }

    #[test]
    fn a_copied_or_hardlinked_shell_is_still_denied_by_name() {
        // A rename does defeat this check, which is exactly why the deny-list
        // is documented as defence in depth rather than the boundary.
        assert!(denies("/tmp/mysh/sh", &[]));
        assert!(!denies("/tmp/definitely-not-a-shell", &[]));
    }

    #[test]
    fn interpreters_are_denied_including_versioned_names() {
        for exe in [
            "/usr/bin/python3",
            "/usr/bin/python3.11",
            "/usr/bin/python2",
            "/usr/bin/perl",
            "/usr/bin/node",
            "/usr/bin/gawk",
        ] {
            assert!(
                classes(exe, &[]).contains(&CapabilityClass::Interpreter),
                "{exe} was permitted"
            );
        }
    }

    #[test]
    fn exec_proxies_are_denied() {
        for exe in [
            "/usr/bin/env",
            "/usr/bin/timeout",
            "/usr/bin/xargs",
            "/usr/bin/flock",
        ] {
            assert!(
                classes(exe, &[]).contains(&CapabilityClass::ExecProxy),
                "{exe} was permitted"
            );
        }
    }

    #[test]
    fn privilege_and_namespace_tools_are_denied() {
        for exe in [
            "/usr/bin/unshare",
            "/usr/sbin/chroot",
            "/usr/bin/systemd-run",
            "/usr/bin/sudo",
        ] {
            assert!(
                classes(exe, &[]).contains(&CapabilityClass::PrivilegeTool),
                "{exe} was permitted"
            );
        }
    }

    #[test]
    fn pagers_and_debuggers_are_denied() {
        for exe in [
            "/usr/bin/less",
            "/usr/bin/man",
            "/usr/bin/find",
            "/usr/bin/gdb",
        ] {
            assert!(
                classes(exe, &[]).contains(&CapabilityClass::ArbitraryRead),
                "{exe} was permitted"
            );
        }
    }

    #[test]
    fn generic_write_primitives_are_denied() {
        for exe in [
            "/usr/bin/tee",
            "/usr/bin/dd",
            "/usr/bin/cp",
            "/usr/bin/ln",
            "/usr/bin/sed",
            "/usr/bin/git",
            "/usr/bin/tar",
            "/usr/bin/curl",
        ] {
            assert!(
                classes(exe, &[]).contains(&CapabilityClass::ArbitraryWrite),
                "{exe} was permitted"
            );
        }
    }

    #[test]
    fn device_and_filesystem_tools_are_denied_including_suffixed_names() {
        assert!(classes("/sbin/mkfs.ext4", &[]).contains(&CapabilityClass::DeviceOrFilesystem));
        assert!(classes("/sbin/wipefs", &[]).contains(&CapabilityClass::DeviceOrFilesystem));
    }

    #[test]
    fn credential_kernel_power_container_security_and_scheduler_tools_are_denied() {
        let cases: [(&str, CapabilityClass); 6] = [
            ("/usr/bin/passwd", CapabilityClass::CredentialTool),
            ("/sbin/modprobe", CapabilityClass::KernelModule),
            ("/sbin/reboot", CapabilityClass::PowerState),
            ("/usr/bin/docker", CapabilityClass::ContainerRuntime),
            ("/usr/sbin/setenforce", CapabilityClass::SecuritySubsystem),
            ("/usr/bin/crontab", CapabilityClass::Scheduler),
        ];
        for (exe, class) in cases {
            assert!(classes(exe, &[]).contains(&class), "{exe} was permitted");
        }
    }

    #[test]
    fn apt_pre_invoke_is_denied_though_no_shell_appears_in_argv() {
        // The motivating case: a rule that only meant to install a package.
        // `sh` is never a command here, it is a configuration value.
        let c = classes(
            "/usr/bin/apt-get",
            &[
                "-o",
                "DPkg::Pre-Invoke::=sh -c 'id > /tmp/pwned'",
                "install",
                "ripgrep",
            ],
        );
        assert!(c.contains(&CapabilityClass::ConfigNamedProgram));
    }

    #[test]
    fn a_bare_package_manager_config_redirect_is_denied() {
        assert!(
            classes("/usr/bin/apt-get", &["-o", "Anything::Here=1"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        assert!(
            classes("/usr/bin/dnf", &["--config-file", "/tmp/evil.repo"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        // The same flag on an unrelated program is not this class.
        assert!(
            !classes("/usr/bin/systemctl", &["-o"]).contains(&CapabilityClass::ConfigNamedProgram)
        );
    }

    #[test]
    fn git_and_ssh_hooks_are_denied_as_config_named_programs() {
        for arg in [
            "core.pager=sh",
            "core.sshCommand=sh",
            "core.editor=vi",
            "ProxyCommand=sh",
            "LocalCommand=sh",
        ] {
            assert!(
                classes("/usr/bin/true", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg} was permitted"
            );
        }
    }

    #[test]
    fn tar_and_rsync_exec_hooks_are_denied() {
        for arg in [
            "--to-command=sh",
            "--checkpoint-action=exec=sh",
            "--use-compress-program=sh",
            "--rsh=sh",
        ] {
            assert!(
                classes("/usr/bin/true", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg} was permitted"
            );
        }
    }

    #[test]
    fn writing_anything_that_decides_is_denied() {
        for path in [
            "/etc/aido/rules.d/99-evil.toml",
            "/etc/sudoers.d/evil",
            "/etc/ld.so.preload",
            "/etc/cron.d/evil",
            "/root/.ssh/authorized_keys",
            "/etc/systemd/system/evil.service",
            "/etc/apt/sources.list.d/evil.list",
            "/var/log/aido/audit.jsonl",
        ] {
            assert!(
                classes("/usr/bin/true", &[path]).contains(&CapabilityClass::SelfModification),
                "{path} was permitted"
            );
        }
    }

    #[test]
    fn a_protected_prefix_matches_the_directory_itself_and_its_children() {
        assert!(touches_protected_path(b"/etc/aido"));
        assert!(touches_protected_path(b"/etc/aido/config.toml"));
        // The prefix-match bug: a sibling whose name merely starts the same.
        assert!(!touches_protected_path(b"/etc/aidoxyz"));
        assert!(!touches_protected_path(b"etc/aido"));
    }

    #[test]
    fn raw_device_targets_are_denied() {
        assert!(
            classes("/usr/bin/true", &["/dev/sda"]).contains(&CapabilityClass::DeviceOrFilesystem)
        );
        assert!(
            classes("/usr/bin/true", &["of=/dev/nvme0n1"])
                .contains(&CapabilityClass::DeviceOrFilesystem)
        );
    }

    #[test]
    fn local_and_remote_package_artefacts_are_denied() {
        for arg in [
            "./local.deb",
            "/tmp/x.rpm",
            "https://evil.example/x.deb",
            "git+https://evil.example/repo",
            "pkg.apk",
            "wheel.whl",
            "src.tar.gz",
        ] {
            assert!(
                classes("/usr/bin/apt-get", &[arg])
                    .contains(&CapabilityClass::UntrustedPackageSource),
                "{arg} was permitted"
            );
        }
    }

    #[test]
    fn fatal_sysctl_keys_are_denied_in_both_spellings() {
        assert!(
            classes("/sbin/sysctl", &["-w", "kernel.core_pattern=|/tmp/x"])
                .contains(&CapabilityClass::SelfModification)
        );
        assert!(
            classes("/sbin/sysctl", &["kernel.modprobe"])
                .contains(&CapabilityClass::SelfModification)
        );
        // A benign tunable is not in this class.
        assert!(
            !classes("/sbin/sysctl", &["-w", "vm.max_map_count=262144"])
                .contains(&CapabilityClass::SelfModification)
        );
    }

    #[test]
    fn file_driven_sysctl_application_is_denied() {
        for flag in ["-p", "--load", "--system"] {
            assert!(
                classes("/sbin/sysctl", &[flag]).contains(&CapabilityClass::ConfigNamedProgram),
                "{flag} was permitted"
            );
        }
        // The same flag on another program is not this class.
        assert!(
            !classes("/usr/bin/systemctl", &["-p"]).contains(&CapabilityClass::ConfigNamedProgram)
        );
    }

    #[test]
    fn unit_mutating_verbs_are_denied_but_lifecycle_verbs_are_not() {
        for verb in [
            "enable",
            "mask",
            "link",
            "edit",
            "set-property",
            "switch-root",
        ] {
            assert!(
                classes("/usr/bin/systemctl", &[verb, "nginx.service"])
                    .contains(&CapabilityClass::UnitDefinitionMutation),
                "{verb} was permitted"
            );
        }
        for verb in ["start", "stop", "restart", "reload", "status"] {
            assert!(
                !classes("/usr/bin/systemctl", &[verb, "nginx.service"])
                    .contains(&CapabilityClass::UnitDefinitionMutation),
                "{verb} was denied"
            );
        }
    }

    #[test]
    fn the_same_verb_on_another_program_is_not_a_unit_mutation() {
        assert!(
            !classes("/usr/bin/apt-get", &["enable"])
                .contains(&CapabilityClass::UnitDefinitionMutation)
        );
    }

    #[test]
    fn findings_are_sorted_and_deduplicated() {
        // The same path at two positions is two findings, deliberately: an
        // investigator needs to know every position that triggered, so the
        // evidence string carries the index and the pair is not a duplicate.
        let repeated = evaluate_deny_list(
            b"/usr/bin/true",
            &Argv::new(vec!["/etc/sudoers", "/etc/sudoers"]),
        );
        assert_eq!(repeated.len(), 2, "{repeated:?}");
        assert!(
            repeated
                .iter()
                .all(|f| f.class == CapabilityClass::SelfModification)
        );

        // Deduplication applies to an identical (class, evidence) pair, which
        // is what happens when one argument trips the same rule twice.
        let once = evaluate_deny_list(b"/usr/bin/true", &Argv::new(vec!["/etc/sudoers"]));
        assert_eq!(once.len(), 1, "{once:?}");

        let distinct = evaluate_deny_list(b"/bin/sh", &Argv::new(vec!["/etc/sudoers", "/dev/sda"]));
        let sorted = distinct
            .windows(2)
            .all(|w| w.first().map(|f| f.class) <= w.get(1).map(|f| f.class));
        assert!(sorted, "{distinct:?}");
        assert!(distinct.len() >= 3);
    }

    #[test]
    fn every_class_states_why_it_is_denied() {
        const ALL: [CapabilityClass; 17] = [
            CapabilityClass::SpawnsShell,
            CapabilityClass::Interpreter,
            CapabilityClass::ExecProxy,
            CapabilityClass::PrivilegeTool,
            CapabilityClass::ArbitraryRead,
            CapabilityClass::ArbitraryWrite,
            CapabilityClass::ConfigNamedProgram,
            CapabilityClass::SelfModification,
            CapabilityClass::DeviceOrFilesystem,
            CapabilityClass::CredentialTool,
            CapabilityClass::KernelModule,
            CapabilityClass::PowerState,
            CapabilityClass::UnitDefinitionMutation,
            CapabilityClass::ContainerRuntime,
            CapabilityClass::SecuritySubsystem,
            CapabilityClass::UntrustedPackageSource,
            CapabilityClass::Scheduler,
        ];
        for class in ALL {
            assert!(class.rationale().len() > 40, "{class:?} rationale is thin");
            let json = serde_json::to_string(&class).unwrap();
            assert_eq!(
                serde_json::from_str::<CapabilityClass>(&json).unwrap(),
                class
            );
            assert!(format!("{class:?}").len() > 3);
        }
    }

    #[test]
    fn findings_serialize_for_the_audit_record() {
        let f = DenyFinding::new(CapabilityClass::SpawnsShell, "executable sh");
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<DenyFinding>(&json).unwrap(), f);
        assert!(format!("{f:?}").contains("SpawnsShell"));
    }

    #[test]
    fn basename_handles_paths_without_a_separator() {
        assert_eq!(basename(b"sh"), b"sh");
        assert_eq!(basename(b"/usr/bin/sh"), b"sh");
        assert_eq!(basename(b"/"), b"");
    }

    #[test]
    fn name_matching_does_not_over_match_unrelated_programs() {
        // `nodejs-doc` is not `node`, and `session` is not `sed`.
        assert!(!matches_name(b"nodejs-doc", INTERPRETERS));
        assert!(!matches_name(b"sedate", ARBITRARY_WRITERS));
        assert!(matches_name(b"node", INTERPRETERS));
    }
}
