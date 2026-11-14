//! The compiled-in deny-list.
//!
//! # Why this is compiled in
//!
//! An allowlist is only as good as its worst entry, and the worst entry is
//! always the one nobody reviewed. This list is therefore part of the binary:
//! it is evaluated *after* allow matching, it cannot be edited, shadowed,
//! disabled, or reordered by any configuration file, and a shipped copy under
//! `/etc/xudo/deny.d/` exists for operators to read, not for the engine to
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
//!
//! Arguments to `systemctl` are classified by the unit name as well as by the
//! verb. A power or boot target, a `modprobe@` template, a filesystem
//! template, this broker's own units, and the `AppArmor` and audit units are
//! refused when the command acts on them. A read-only verb (`status`, `show`,
//! and the other queries) is exempt, including when the unit is on this list.
//! The exemption holds only when no token acts: an option value must not hide
//! `stop` or `poweroff`. A rule that matches the generic unit-name kind cannot
//! reopen an acting use.

use bstr::ByteSlice;
use serde::{Deserialize, Serialize};

use crate::argv::Argv;

/// Version of the compiled-in list, recorded in every audit record.
///
/// Bump on every change, so a decision can be replayed against the exact list
/// that produced it.
pub fn deny_list_version() -> u32 {
    4
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
    /// Writes any file that decides what is permitted, including xudo's own.
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
                 check, including xudo's own"
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
                 root that outlives xudo"
            }
            Self::KernelModule => {
                "loaded kernel code is above every userspace control, xudo included"
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
    b"/etc/xudo",
    b"/usr/libexec/xudo",
    b"/var/log/xudo",
    b"/var/lib/xudo",
    b"/run/xudo",
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

/// Power and boot targets. `systemctl start` of one of these changes whether
/// the machine is up, or which mode it comes up in. Matched case-sensitively,
/// as systemd matches unit names.
///
/// `hybrid-sleep`, `suspend-then-hibernate`, `sleep`, and `shutdown` are the
/// same power act as `suspend` and `poweroff`. `sysinit` is the early-boot
/// target. Ordinary dependency targets (`multi-user`, `network`) are not in
/// this list. Runlevel aliases are [`RUNLEVELS`]: `runlevel0` is poweroff,
/// `runlevel6` is reboot, and `runlevel1` is rescue.
const POWER_OR_BOOT_TARGETS: &[&[u8]] = &[
    b"poweroff.target",
    b"reboot.target",
    b"halt.target",
    b"kexec.target",
    b"soft-reboot.target",
    b"ctrl-alt-del.target",
    b"suspend.target",
    b"hibernate.target",
    b"hybrid-sleep.target",
    b"suspend-then-hibernate.target",
    b"sleep.target",
    b"shutdown.target",
    b"rescue.target",
    b"emergency.target",
    b"exit.target",
    b"sysinit.target",
    // Late shutdown. `CanStart` is no on the probed images; the name is
    // still the unit a lifecycle rule would act on.
    b"umount.target",
    b"final.target",
];

/// `runlevel0` (poweroff), `runlevel1` (rescue), `runlevel6` (reboot).
///
/// These are aliases of the special targets. A name match on
/// `poweroff.target` alone misses `runlevel0.target`.
const RUNLEVELS: &[&[u8]] = &[b"runlevel0", b"runlevel1", b"runlevel6"];

/// Services that implement a power or sleep target.
///
/// `systemd-poweroff.service` is a different unit from `poweroff.target`, and
/// a `.service`-only rule still accepts it. The stem is matched, so the bare
/// name systemd resolves to `stem.service` is the same unit.
const POWER_SERVICES: &[&[u8]] = &[
    b"systemd-poweroff",
    b"systemd-reboot",
    b"systemd-halt",
    b"systemd-kexec",
    b"systemd-soft-reboot",
    b"systemd-suspend",
    b"systemd-hibernate",
    b"systemd-hybrid-sleep",
    b"systemd-suspend-then-hibernate",
    // SuccessAction=exit-force. Starting it reboots the host.
    b"systemd-exit",
    // The services behind rescue.target and emergency.target. The targets
    // are listed above; these names are the `.service` units.
    b"rescue",
    b"emergency",
];

/// `debug-shell.service` is an unauthenticated root shell on tty9.
const SHELL_UNITS: &[&[u8]] = &[b"debug-shell"];

/// Template prefixes whose instance is a kernel module name.
const KERNEL_MODULE_TEMPLATES: &[&[u8]] = &[b"modprobe"];

/// Template prefixes that check, grow, or create a filesystem.
const DEVICE_TEMPLATES: &[&[u8]] = &[b"systemd-fsck", b"systemd-growfs", b"systemd-makefs"];

/// A service that repartitions a disk. Not a template, so the `@` list misses it.
const DEVICE_SERVICES: &[&[u8]] = &[b"systemd-repart"];

/// Applies the sysctl files at boot. Same class as a file-driven `sysctl` flag.
const SYSCTL_UNITS: &[&[u8]] = &[b"systemd-sysctl"];

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

/// `systemctl` subcommands that power off, reboot, sleep, or change the boot
/// target. Refused with no unit argument, wherever the word sits. `isolate`
/// is one of them for every target, including a target this list does not name.
///
/// `sleep` is the combined sleep verb from systemd 256. The stock Debian and
/// Ubuntu images used for the check do not ship `systemctl`, so this was not
/// observed in `--help`. Refusing a word the binary would reject is harmless.
/// `status rescue` is refused with these: a suffix-less unit whose name is a
/// power word is the cost of not trusting the first non-flag token.
const POWER_SUBCOMMANDS: &[&[u8]] = &[
    b"poweroff",
    b"reboot",
    b"halt",
    b"kexec",
    b"suspend",
    b"hibernate",
    b"hybrid-sleep",
    b"suspend-then-hibernate",
    b"soft-reboot",
    b"sleep",
    b"rescue",
    b"emergency",
    b"default",
    b"exit",
    b"isolate",
];

/// Verbs that start, stop, reload, or signal a unit.
///
/// A token in this list is not a unit name. `systemctl -p status stop
/// debug-shell.service` is `stop`: the value of `-p` must not hide it.
/// `kill`, `clean`, `freeze`, and `thaw` are acting verbs. The compatibility
/// names are the LSB aliases `systemctl` still accepts. The stock images do
/// not ship `systemctl`, so those names were not observed in `--help`. Keeping
/// them refuses a verb the binary would reject, which is harmless.
const ACTING_SYSTEMCTL_VERBS: &[&[u8]] = &[
    b"start",
    b"stop",
    b"restart",
    b"try-restart",
    b"reload",
    b"reload-or-restart",
    b"try-reload-or-restart",
    b"kill",
    b"clean",
    b"freeze",
    b"thaw",
    b"condrestart",
    b"force-reload",
    b"reload-or-try-restart",
    b"condreload",
    b"condstop",
];

/// Verbs that only read unit state.
///
/// The unit tripwire does not apply when every non-flag token is one of these
/// or a unit name, at least one of these is present, and no token is an
/// acting, mutating, or power verb. A power subcommand is not in this list,
/// so `systemctl poweroff` stays refused.
const READ_ONLY_SYSTEMCTL_VERBS: &[&[u8]] = &[
    b"status",
    b"show",
    b"is-active",
    b"is-failed",
    b"is-enabled",
    b"cat",
    b"list-units",
    b"list-unit-files",
    b"list-dependencies",
    b"list-sockets",
    b"list-timers",
    b"list-jobs",
];

fn is_flag_token(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'-')
}

/// A token that can be a unit name or the value of an option.
///
/// Acting and power verbs are excluded by the caller before this runs. An
/// option value such as `now` or `root@host` lands here, which is safe: the
/// acting verb, if there is one, is a different token and is checked on its
/// own. A byte a unit name cannot hold (`/`, `=`) is an unknown verb.
fn is_unit_ish(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@' | b'\\' | b':')
        })
}

/// Any non-flag token that is a power or boot subcommand.
///
/// systemctl's getopt takes the next argument as the value of `-p`, `-M`,
/// `--when`, and the other options that take a separate value. The real verb
/// can sit later. The first non-flag token is not the verb.
fn systemctl_power_subcommand(argv: &Argv) -> Option<&[u8]> {
    argv.as_slice().iter().find_map(|arg| {
        let bytes = arg.as_bytes();
        if is_flag_token(bytes) || !POWER_SUBCOMMANDS.contains(&bytes) {
            None
        } else {
            Some(bytes)
        }
    })
}

/// `--job-mode=isolate`, a unique prefix of that option, or the split form.
///
/// `start --job-mode=isolate` stops every other unit. The value is not its
/// own token in the joined form, so the power-word scan does not see it.
/// The split form (`--job-mode isolate`) is also a bare `isolate` token.
fn job_mode_isolate(argv: &Argv) -> bool {
    let tokens = argv.as_slice();
    for (index, arg) in tokens.iter().enumerate() {
        let bytes = arg.as_bytes();
        if !long_option_prefix(bytes, b"job-mode") {
            continue;
        }
        if let Some((_, value)) = bytes.split_once_str(b"=") {
            if value == b"isolate" {
                return true;
            }
            continue;
        }
        if tokens
            .get(index.saturating_add(1))
            .is_some_and(|next| next.as_bytes() == b"isolate")
        {
            return true;
        }
    }
    false
}

/// Whether the command only reads state.
///
/// True only when at least one read-only verb is present, every other
/// non-flag token is a unit name (or an option value of that shape), and no
/// token is an acting, mutating, or power verb. An unknown verb fails closed:
/// the unit tripwire applies.
fn systemctl_read_only(argv: &Argv) -> bool {
    let mut saw_read_only = false;
    for arg in argv.as_slice() {
        let bytes = arg.as_bytes();
        if is_flag_token(bytes) {
            continue;
        }
        if POWER_SUBCOMMANDS.contains(&bytes)
            || UNIT_MUTATING_VERBS.contains(&bytes)
            || ACTING_SYSTEMCTL_VERBS.contains(&bytes)
        {
            return false;
        }
        if READ_ONLY_SYSTEMCTL_VERBS.contains(&bytes) {
            saw_read_only = true;
            continue;
        }
        if !is_unit_ish(bytes) {
            return false;
        }
    }
    saw_read_only
}

/// One hexadecimal digit, or `None` when `byte` is not one.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Some(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// A complete `\xHH` at the start of `bytes`, and what follows it.
fn take_hex_byte(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (hi, rest) = bytes.split_first()?;
    let (lo, rest) = rest.split_first()?;
    let hi = hex_nibble(*hi)?;
    let lo = hex_nibble(*lo)?;
    // Each nibble is 0..=15, so the byte they form fits in `u8`.
    Some((hi.saturating_mul(16).saturating_add(lo), rest))
}

/// Decodes systemd `\xHH` escapes in a unit name.
///
/// A backslash that is not a complete `\xHH` is ambiguous. `drop_escaped`
/// drops both the backslash and the byte after it, so `mod\.probe` joins
/// into `modprobe`. Otherwise only the backslash is dropped, so
/// `poweroff\.target` is `poweroff.target`. Either reading is enough to
/// deny: an escape that can spell a refused unit is refused.
///
/// A trailing backslash has no byte after it and is dropped.
fn decode_unit(bytes: &[u8], drop_escaped: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&head, tail)) = rest.split_first() {
        if head != b'\\' {
            out.push(head);
            rest = tail;
            continue;
        }
        // A match, not `let … else`: the diverging `else` is a region
        // llvm-cov does not mark covered even when a trailing `\` hits it.
        match tail.split_first() {
            None => break,
            Some((&marker, after)) => {
                if marker == b'x'
                    && let Some((byte, after_byte)) = take_hex_byte(after)
                {
                    out.push(byte);
                    rest = after_byte;
                    continue;
                }
                if !drop_escaped {
                    out.push(marker);
                }
                rest = after;
            }
        }
    }
    out
}

/// The template name before the first `@`, when there is one.
fn template_prefix(unit: &[u8]) -> Option<&[u8]> {
    match unit.split_once_str(b"@") {
        Some((prefix, _)) if !prefix.is_empty() => Some(prefix),
        Some(_) | None => None,
    }
}

/// The capability a template unit exercises, from its prefix alone.
///
/// The instance is not consulted. `modprobe@` loads whatever module the
/// instance names, and an instance that contains `\` is the same template
/// with a name this list will not try to decode before refusing it.
fn template_class(unit: &[u8]) -> Option<CapabilityClass> {
    let prefix = template_prefix(unit)?;
    if KERNEL_MODULE_TEMPLATES.contains(&prefix) {
        Some(CapabilityClass::KernelModule)
    } else if DEVICE_TEMPLATES.contains(&prefix) || prefix.starts_with(b"mdadm") {
        Some(CapabilityClass::DeviceOrFilesystem)
    } else {
        None
    }
}

/// `stem`, `stem.something`, or `stem@instance`.
///
/// systemd resolves a suffix-less name to `stem.service`, so the bare stem
/// is the same unit as `stem.service`.
fn has_unit_stem(unit: &[u8], stem: &[u8]) -> bool {
    match unit.strip_prefix(stem) {
        Some(rest) if rest.is_empty() || rest.starts_with(b".") || rest.starts_with(b"@") => true,
        Some(_) | None => false,
    }
}

/// Stems of xudo's own units, and of the log path its audit mirror uses.
///
/// Stopping the broker socket removes the policy that allowed the command.
/// The journal itself is [`is_journal_unit`]: `systemd-journald` followed by
/// `-`, `.`, or `@` is that journal for any continuation, including
/// `-audit` and `-dev-log`. `rsyslog` is the same log path on a host that
/// forwards the journal. `syslog.socket` is the logging socket on the
/// probed Debian and Ubuntu images. `syslog.service` was not installed
/// there; the stem still covers that name.
const AUDIT_MIRROR_UNITS: &[&[u8]] = &[b"rsyslog", b"syslog"];

/// `systemd-journald`, and any continuation after `-`, `.`, or `@`.
///
/// `-audit` and `-dev-log` are the same daemon. A neighbour that does not
/// continue the stem (`systemd-journaldctl`) is not.
fn is_journal_unit(unit: &[u8]) -> bool {
    match unit.strip_prefix(b"systemd-journald") {
        Some(rest)
            if rest.is_empty()
                || rest.starts_with(b"-")
                || rest.starts_with(b".")
                || rest.starts_with(b"@") =>
        {
            true
        }
        Some(_) | None => false,
    }
}

/// Firewall and time-sync stems, plus `AppArmor` and auditd.
///
/// Stopping a firewall unit removes a host security control, which is what
/// [`CapabilityClass::SecuritySubsystem`] is for. Stopping a time-sync unit
/// is the same act as `set-ntp false`. There is no time-sync class; this one
/// is the class for disabling a host control, and
/// [`CapabilityClass::SelfModification`] stays the class for xudo's own
/// policy and audit path.
const SECURITY_UNITS: &[&[u8]] = &[
    b"apparmor",
    b"auditd",
    b"nftables",
    b"ufw",
    b"netfilter-persistent",
    b"firewalld",
    b"systemd-timesyncd",
    // Alias of systemd-timesyncd.service on the probed images. The stem
    // `systemd-timesyncd` does not match this name.
    b"dbus-org.freedesktop.timesync1",
    b"chrony",
    b"chronyd",
];

/// xudo's own units. Stopping the broker socket, or an `xudo-*` service,
/// removes the policy that allowed the command. The journal stems are the
/// audit mirror; see [`AUDIT_MIRROR_UNITS`].
fn is_self_unit(unit: &[u8]) -> bool {
    has_unit_stem(unit, b"xudod")
        || unit.starts_with(b"xudo-")
        || is_journal_unit(unit)
        || stem_in(unit, AUDIT_MIRROR_UNITS)
}

/// A firewall, time-sync, `AppArmor`, or audit unit.
fn is_security_unit(unit: &[u8]) -> bool {
    stem_in(unit, SECURITY_UNITS)
}

/// Whether `unit` is `stem`, `stem.something`, or `stem@instance`.
fn stem_in(unit: &[u8], stems: &[&[u8]]) -> bool {
    stems.iter().any(|stem| has_unit_stem(unit, stem))
}

/// The capability class of one unit name, after escapes have been decoded.
fn class_of_unit(unit: &[u8]) -> Option<CapabilityClass> {
    // Every power-target entry ends in `.target`. Skipping that list for any
    // other suffix keeps the common service-name path to a couple of compares.
    // Runlevels are stems: `runlevel0.target` and the bare name both match.
    if unit.ends_with(b".target") && POWER_OR_BOOT_TARGETS.contains(&unit) {
        return Some(CapabilityClass::PowerState);
    }
    if stem_in(unit, RUNLEVELS) || stem_in(unit, POWER_SERVICES) {
        return Some(CapabilityClass::PowerState);
    }
    if let Some(class) = template_class(unit) {
        return Some(class);
    }
    if stem_in(unit, DEVICE_SERVICES) {
        return Some(CapabilityClass::DeviceOrFilesystem);
    }
    if stem_in(unit, SHELL_UNITS) {
        return Some(CapabilityClass::SpawnsShell);
    }
    if is_self_unit(unit) {
        return Some(CapabilityClass::SelfModification);
    }
    if is_security_unit(unit) {
        return Some(CapabilityClass::SecuritySubsystem);
    }
    if stem_in(unit, SYSCTL_UNITS) {
        return Some(CapabilityClass::ConfigNamedProgram);
    }
    None
}

/// The class of one `systemctl` argument, when it names a unit this list
/// refuses.
///
/// Flags are not units. The raw bytes are tried first, which already refuses
/// a template whose instance contains `\`. A name that still contains `\` is
/// then read both ways [`decode_unit`] documents, and refused when either
/// reading is a unit this list refuses. The comparison is case-sensitive.
fn classify_systemctl_unit(raw: &[u8]) -> Option<CapabilityClass> {
    if raw.first() == Some(&b'-') {
        return None;
    }
    if let Some(class) = class_of_unit(raw) {
        return Some(class);
    }
    if !raw.contains(&b'\\') {
        return None;
    }
    for drop_escaped in [false, true] {
        // `\` is always consumed, so this is a different name from `raw`,
        // which `class_of_unit` has already refused to classify.
        if let Some(class) = class_of_unit(&decode_unit(raw, drop_escaped)) {
            return Some(class);
        }
    }
    None
}

/// Extracts the final path component of an executable path.
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit_str(b"/").next().unwrap_or(path)
}

/// Verbs that start, stop, reload, isolate, or power the machine.
///
/// A rule whose `systemctl` verb position accepts one of these, followed by a
/// unit position that is not a finite list, can act on a unit the operator
/// did not name. `xudo check` reports that. The power words are also the
/// subcommands `systemctl` accepts with no unit argument.
pub(crate) const LIFECYCLE_OR_POWER_VERBS: &[&[u8]] = &[
    b"start",
    b"stop",
    b"restart",
    b"try-restart",
    b"reload",
    b"reload-or-restart",
    b"try-reload-or-restart",
    b"kill",
    b"clean",
    b"freeze",
    b"thaw",
    b"condrestart",
    b"force-reload",
    b"reload-or-try-restart",
    b"condreload",
    b"condstop",
    b"isolate",
    b"poweroff",
    b"reboot",
    b"halt",
    b"kexec",
    b"suspend",
    b"hibernate",
    b"hybrid-sleep",
    b"suspend-then-hibernate",
    b"soft-reboot",
    b"sleep",
    b"rescue",
    b"emergency",
    b"default",
    b"exit",
];

/// Whether `exe` is `systemctl` by basename, byte for byte.
pub(crate) fn exe_is_systemctl(exe: &[u8]) -> bool {
    basename(exe) == b"systemctl"
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

/// ASCII case fold for apt, which compares long options with `stringcasecmp`.
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

/// Whether a short-option cluster contains one of `letters`.
///
/// The cluster is the leading ASCII letters after a single `-`. `-yc/tmp`
/// clusters `y` and `c`; the value starts at the first non-letter. `--option`
/// is a long option and is not a cluster. A path byte is not a cluster letter,
/// so `-y/tmp/cache` does not match `c`.
fn short_cluster_has(bytes: &[u8], letters: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"-") else {
        return false;
    };
    if rest.is_empty() || rest.starts_with(b"-") {
        return false;
    }
    for byte in rest {
        if !byte.is_ascii_alphabetic() {
            return false;
        }
        if letters.contains(byte) {
            return true;
        }
    }
    false
}

/// The name of a long option, without a joined `=value`.
fn long_option_name(bytes: &[u8]) -> Option<&[u8]> {
    let rest = bytes.strip_prefix(b"--")?;
    if rest.is_empty() {
        return None;
    }
    Some(match rest.split_once_str(b"=") {
        Some((name, _)) => name,
        None => rest,
    })
}

/// `bytes` names `option` exactly. Apt compares that name without regard to case.
fn long_option_is(bytes: &[u8], option: &[u8], ignore_case: bool) -> bool {
    let Some(name) = long_option_name(bytes) else {
        return false;
    };
    if ignore_case {
        ascii_eq_ignore_case(name, option)
    } else {
        name == option
    }
}

/// `bytes` is a non-empty abbreviation of `option`, or the option itself.
///
/// `--load-extra` is not an abbreviation of `--load`: the name is longer than
/// the option. `getopt_long` accepts a unique prefix; `load` and `system` do
/// not share one.
fn long_option_prefix(bytes: &[u8], option: &[u8]) -> bool {
    let Some(name) = long_option_name(bytes) else {
        return false;
    };
    !name.is_empty() && name.len() <= option.len() && option.starts_with(name)
}

/// apt and apt-get. Long names are case-insensitive. `-c` and `-o` match
/// inside a short cluster.
fn apt_redirects_config(bytes: &[u8]) -> bool {
    short_cluster_has(bytes, b"co")
        || long_option_is(bytes, b"option", true)
        || long_option_is(bytes, b"config-file", true)
}

/// dnf and yum. `-c` is their short form of `--config`.
///
/// Argparse accepts a unique prefix, so `--conf=` is `--config` and
/// `--setop=` is `--setopt`. `--installroot` and `--repofrompath` point the
/// transaction at another root or another repository. dnf and yum were not
/// installed on the probed images; the refusal is the conservative one.
fn dnf_redirects_config(bytes: &[u8]) -> bool {
    short_cluster_has(bytes, b"c")
        || long_option_prefix(bytes, b"config")
        || long_option_prefix(bytes, b"setopt")
        || long_option_prefix(bytes, b"installroot")
        || long_option_prefix(bytes, b"repofrompath")
}

/// zypper: `-c`, `--config`, `--root`, and `--plus-repo`.
///
/// `--root` and `--plus-repo` were not checked on a zypper binary. Refusing
/// them is the conservative reading of a root and an extra repository.
fn zypper_redirects_config(bytes: &[u8]) -> bool {
    short_cluster_has(bytes, b"c")
        || long_option_prefix(bytes, b"config")
        || long_option_prefix(bytes, b"root")
        || long_option_prefix(bytes, b"plus-repo")
}

/// pacman config, hooks, root, database, and sysroot.
///
/// `-c` is pacman's `--clean` or `--cascade`, not a config file. Refusing
/// that letter is harmless: it does not point pacman at another configuration,
/// and a rule that meant to allow a clean still cannot retarget the database.
/// `--hook` is a getopt prefix of `--hookdir`. `-r` is `--root` and `-b` is
/// `--dbpath`. pacman was not installed on the probed images.
fn pacman_redirects_config(bytes: &[u8]) -> bool {
    short_cluster_has(bytes, b"crb")
        || long_option_prefix(bytes, b"config")
        || long_option_prefix(bytes, b"hookdir")
        || long_option_prefix(bytes, b"root")
        || long_option_prefix(bytes, b"dbpath")
        || long_option_prefix(bytes, b"sysroot")
}

/// dpkg's own redirects. Apt's `-o` and `--config-file` are not dpkg options.
///
/// `--status-logger` runs a command. `--log` names the file those actions are
/// written to. Both are in `dpkg --help` on Debian 13.
fn dpkg_redirects_config(bytes: &[u8]) -> bool {
    long_option_is(bytes, b"admindir", false)
        || long_option_is(bytes, b"instdir", false)
        || long_option_is(bytes, b"root", false)
        || long_option_is(bytes, b"pre-invoke", false)
        || long_option_is(bytes, b"post-invoke", false)
        || long_option_prefix(bytes, b"status-logger")
        || long_option_prefix(bytes, b"log")
}

/// A package-manager argument that points config, hooks, or the root elsewhere.
fn redirects_package_config(tool: &[u8], bytes: &[u8]) -> bool {
    match tool {
        b"apt" | b"apt-get" => apt_redirects_config(bytes),
        b"dnf" | b"yum" => dnf_redirects_config(bytes),
        b"zypper" => zypper_redirects_config(bytes),
        b"pacman" => pacman_redirects_config(bytes),
        b"dpkg" => dpkg_redirects_config(bytes),
        _ => false,
    }
}

/// sysctl's file-driven flags, including `-f` (an alias of `-p`), a short
/// cluster that contains `p` or `f`, and a unique prefix of `--load` or
/// `--system`.
fn applies_sysctl_file(bytes: &[u8]) -> bool {
    short_cluster_has(bytes, b"pf")
        || long_option_prefix(bytes, b"load")
        || long_option_prefix(bytes, b"system")
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
/// it. `argv` must already be canonicalized. Canonicalization does **not**
/// split `--key=value` (see [`crate::argv::Argv::canonicalize`]): a joined
/// flag is one argument, so a flag this list refuses is matched both as an
/// exact token and as the joined prefix `--flag=` or `-xVALUE`.
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

/// `systemctl poweroff` has no unit. `isolate` of an ordinary target is the
/// same act, and so is `--job-mode=isolate`. The subcommand is any non-flag
/// token: an option that takes a separate value does not hide it.
fn power_subcommand_finding(name: &[u8], argv: &Argv) -> Option<DenyFinding> {
    if name != b"systemctl" {
        return None;
    }
    if let Some(verb) = systemctl_power_subcommand(argv) {
        return Some(DenyFinding::new(
            CapabilityClass::PowerState,
            format!("systemctl {} changes power or boot state", verb.as_bstr()),
        ));
    }
    if job_mode_isolate(argv) {
        return Some(DenyFinding::new(
            CapabilityClass::PowerState,
            "systemctl --job-mode=isolate changes power or boot state",
        ));
    }
    None
}

/// Classes implied by the shape of the arguments.
///
/// `name` is consulted only where a flag's meaning depends on which program
/// receives it: `-p` is fatal to `sysctl` and harmless to `systemctl`.
fn deny_by_arguments(name: &[u8], argv: &Argv) -> Vec<DenyFinding> {
    let mut findings: Vec<DenyFinding> = Vec::new();
    if let Some(finding) = power_subcommand_finding(name, argv) {
        findings.push(finding);
    }
    // Once per command. The unit tripwire asks the same question for every
    // argument, and an option value must not change the answer halfway through.
    let systemctl_reads = name == b"systemctl" && systemctl_read_only(argv);
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
        // argv does not name, so argv matching cannot see them. `-p/path` and
        // `--load=/path` are the joined spellings of the same flags.
        // `--system=` is refused with them: it is the joined form of a flag
        // this list already refuses, and a value there is still a file.
        if name == b"sysctl" && applies_sysctl_file(bytes) {
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

        // A unit an acting verb would start, stop, or signal. Read-only verbs
        // are exempt: diagnosing these units is not a hole. Power subcommands
        // are refused above. This still refuses a listed unit an operator named.
        if name == b"systemctl"
            && !systemctl_reads
            && let Some(class) = classify_systemctl_unit(bytes)
        {
            findings.push(DenyFinding::new(
                class,
                format!(
                    "argument {index} names the restricted unit {}",
                    bytes.as_bstr()
                ),
            ));
        }

        // An option that redirects a package manager's configuration, hooks, or
        // root. Each tool has its own spellings. apt folds long-option case
        // and clusters short options; the others do not use apt's names.
        if redirects_package_config(name, bytes) {
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
        assert_eq!(deny_list_version(), 4);
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
            classes("/usr/bin/dnf", &["--config", "/tmp/evil.repo"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        // The same flag on an unrelated program is not this class.
        assert!(
            !classes("/usr/bin/systemctl", &["-o"]).contains(&CapabilityClass::ConfigNamedProgram)
        );
        // `--config-file` is apt's spelling. dnf's flag is `--config`.
        #[cfg(not(miri))]
        assert!(
            !classes("/usr/bin/dnf", &["--config-file", "/tmp/evil.repo"])
                .contains(&CapabilityClass::ConfigNamedProgram)
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
            "/etc/xudo/rules.d/99-evil.toml",
            "/etc/sudoers.d/evil",
            "/etc/ld.so.preload",
            "/etc/cron.d/evil",
            "/root/.ssh/authorized_keys",
            "/etc/systemd/system/evil.service",
            "/etc/apt/sources.list.d/evil.list",
            "/var/log/xudo/audit.jsonl",
            "/var/lib/xudo/audit.jsonl",
        ] {
            assert!(
                classes("/usr/bin/true", &[path]).contains(&CapabilityClass::SelfModification),
                "{path} was permitted"
            );
        }
    }

    #[test]
    fn a_protected_prefix_matches_the_directory_itself_and_its_children() {
        assert!(touches_protected_path(b"/etc/xudo"));
        assert!(touches_protected_path(b"/etc/xudo/config.toml"));
        // The prefix-match bug: a sibling whose name merely starts the same.
        assert!(!touches_protected_path(b"/etc/xudoxyz"));
        assert!(!touches_protected_path(b"etc/xudo"));
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

    #[test]
    fn denies_poweroff_via_systemctl_start_poweroff_target() {
        let found = classes(
            "/usr/bin/systemctl",
            &[
                "--no-pager",
                "--no-ask-password",
                "start",
                "poweroff.target",
            ],
        );
        assert!(found.contains(&CapabilityClass::PowerState), "{found:?}");
        assert!(!found.contains(&CapabilityClass::UnitDefinitionMutation));
        // A different case is a different unit. systemd does not fold it.
        assert!(!denies("/usr/bin/systemctl", &["start", "Poweroff.target"]));
    }

    #[test]
    fn denies_systemctl_poweroff_subcommand() {
        assert!(
            classes("/usr/bin/systemctl", &["--no-wall", "poweroff"])
                .contains(&CapabilityClass::PowerState)
        );
        assert!(systemctl_power_subcommand(&Argv::default()).is_none());
        assert!(systemctl_power_subcommand(&Argv::new(vec!["--no-pager"])).is_none());
        assert!(systemctl_power_subcommand(&Argv::new(vec!["start"])).is_none());
        // The value of an option is not the verb. The power word can sit later.
        assert_eq!(
            systemctl_power_subcommand(&Argv::new(vec!["-p", "x", "poweroff"])),
            Some(b"poweroff".as_slice())
        );
        assert_eq!(
            systemctl_power_subcommand(&Argv::new(vec!["--when", "now", "sleep"])),
            Some(b"sleep".as_slice())
        );
    }

    #[test]
    fn systemctl_verb_sets_do_not_overlap_and_the_lint_list_covers_them() {
        for verb in READ_ONLY_SYSTEMCTL_VERBS {
            // Built on the success path. A format argument runs only when the
            // assertion fails, and that region would be uncovered.
            let name = verb.as_bstr();
            assert!(!POWER_SUBCOMMANDS.contains(verb), "{name}");
            assert!(!ACTING_SYSTEMCTL_VERBS.contains(verb), "{name}");
            assert!(!UNIT_MUTATING_VERBS.contains(verb), "{name}");
        }
        for verb in ACTING_SYSTEMCTL_VERBS {
            let name = verb.as_bstr();
            assert!(!POWER_SUBCOMMANDS.contains(verb), "{name}");
        }
        for verb in POWER_SUBCOMMANDS
            .iter()
            .chain(ACTING_SYSTEMCTL_VERBS.iter())
        {
            // The name is formatted on the success path. A format argument
            // that runs only when the assertion fails is an uncovered line.
            let name = verb.as_bstr();
            assert!(LIFECYCLE_OR_POWER_VERBS.contains(verb), "{name}");
        }
    }

    #[test]
    fn an_option_value_cannot_hide_the_verb() {
        // Pure checks. The option × verb matrix lives in the integration
        // tests, where miri does not pay for `evaluate_deny_list`.
        assert!(job_mode_isolate(&Argv::new(vec![
            "start",
            "--job-mode=isolate",
            "nginx.service",
        ])));
        assert!(job_mode_isolate(&Argv::new(vec![
            "start",
            "--j=isolate",
            "nginx.service",
        ])));
        assert!(job_mode_isolate(&Argv::new(vec![
            "start",
            "--job-mode",
            "isolate",
        ])));
        assert!(!job_mode_isolate(&Argv::new(vec![
            "start",
            "--job-mode=replace",
            "nginx.service",
        ])));
        assert!(!job_mode_isolate(&Argv::new(vec!["start", "--job-mode"])));
        assert!(!job_mode_isolate(&Argv::new(vec![
            "start",
            "--json=isolate",
            "nginx.service",
        ])));
        assert!(systemctl_read_only(&Argv::new(vec![
            "status",
            "xudod.socket"
        ])));
        assert!(systemctl_read_only(&Argv::new(vec![
            "--no-pager",
            "--full",
            "status",
            "journald",
        ])));
        assert!(systemctl_read_only(&Argv::new(vec![
            "-p",
            "ActiveState",
            "status",
            "xudod.socket",
        ])));
        assert!(!systemctl_read_only(&Argv::new(vec![
            "-p",
            "status",
            "stop",
            "debug-shell.service",
        ])));
        assert!(!systemctl_read_only(&Argv::new(vec!["status", "rescue"])));
        assert!(!systemctl_read_only(&Argv::new(vec!["status", "enable"])));
        assert!(!systemctl_read_only(&Argv::new(vec!["status", "a/b"])));
        assert!(!systemctl_read_only(&Argv::new(vec!["nginx.service"])));
        assert!(!is_unit_ish(b""));
        assert!(is_unit_ish(b"root@host"));
        // The finding text is pinned here, off the miri path. Each
        // `evaluate_deny_list` is most of a second there. The integration
        // matrix names every option and verb.
        #[cfg(not(miri))]
        {
            let hidden = classes(
                "/usr/bin/systemctl",
                &["-p", "status", "stop", "debug-shell.service"],
            );
            assert!(hidden.contains(&CapabilityClass::SpawnsShell), "{hidden:?}");
            let isolate = evaluate_deny_list(
                b"/usr/bin/systemctl",
                &Argv::new(vec!["start", "--job-mode=isolate", "nginx.service"]),
            );
            assert!(
                isolate
                    .iter()
                    .any(|finding| finding.evidence.contains("job-mode=isolate")),
                "{isolate:?}"
            );
            assert!(
                evaluate_deny_list(
                    b"/usr/bin/systemctl",
                    &Argv::new(vec!["status", "xudod.socket"])
                )
                .is_empty()
            );
            assert!(
                evaluate_deny_list(
                    b"/usr/bin/systemctl",
                    &Argv::new(vec!["--no-pager", "--full", "status", "journald"])
                )
                .is_empty()
            );
            assert!(
                classes("/usr/bin/systemctl", &["status", "rescue"])
                    .contains(&CapabilityClass::PowerState)
            );
        }
    }

    #[test]
    fn denies_isolate_of_any_target() {
        assert!(
            classes("/usr/bin/systemctl", &["isolate", "multi-user.target"])
                .contains(&CapabilityClass::PowerState)
        );
    }

    #[test]
    fn denies_kernel_module_load_via_modprobe_template_unit() {
        assert!(
            classes("/usr/bin/systemctl", &["start", "modprobe@dummy.service"])
                .contains(&CapabilityClass::KernelModule)
        );
        // `\x40` is `@`. One escaped spelling here keeps the decoder on the
        // miri path; the rest of the matrix lives in the integration tests.
        assert!(
            classes(
                "/usr/bin/systemctl",
                &["start", "modprobe\\x40dummy.service"]
            )
            .contains(&CapabilityClass::KernelModule)
        );
    }

    #[test]
    fn denies_stopping_the_broker_socket() {
        assert!(
            classes("/usr/bin/systemctl", &["stop", "xudod.socket"])
                .contains(&CapabilityClass::SelfModification)
        );
    }

    #[test]
    fn denies_poweroff_via_systemd_poweroff_service() {
        // One service and one runlevel alias under miri: each extra
        // `evaluate_deny_list` is most of a second there, and the integration
        // property already names every listed unit.
        #[cfg(miri)]
        let units: &[&str] = &["systemd-poweroff.service", "runlevel0.target"];
        #[cfg(not(miri))]
        let units: &[&str] = &[
            "systemd-poweroff.service",
            "systemd-reboot.service",
            "systemd-halt.service",
            "systemd-kexec.service",
            "systemd-soft-reboot.service",
            "systemd-suspend.service",
            "systemd-hibernate.service",
            "systemd-hybrid-sleep.service",
            "systemd-suspend-then-hibernate.service",
            "systemd-exit.service",
            "rescue.service",
            "emergency.service",
            "umount.target",
            "final.target",
            "runlevel0.target",
            "runlevel1.target",
            "runlevel6.target",
            "systemd-poweroff",
        ];
        for unit in units {
            assert!(
                classes("/usr/bin/systemctl", &["start", unit])
                    .contains(&CapabilityClass::PowerState),
                "{unit}"
            );
        }
        assert!(!denies("/usr/bin/systemctl", &["start", "nginx.service"]));
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_repart_sysctl_and_keeps_status_of_a_new_unit() {
        assert!(
            classes("/usr/bin/systemctl", &["start", "systemd-repart.service"])
                .contains(&CapabilityClass::DeviceOrFilesystem)
        );
        assert!(
            classes("/usr/bin/systemctl", &["restart", "systemd-sysctl.service"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        assert!(
            evaluate_deny_list(
                b"/usr/bin/systemctl",
                &Argv::new(vec!["status", "umount.target"])
            )
            .is_empty()
        );
    }

    #[test]
    fn denies_debug_shell_service() {
        assert!(
            classes("/usr/bin/systemctl", &["start", "debug-shell.service"])
                .contains(&CapabilityClass::SpawnsShell)
        );
        assert!(
            classes("/usr/bin/systemctl", &["start", "debug-shell"])
                .contains(&CapabilityClass::SpawnsShell)
        );
    }

    #[test]
    fn firewall_time_sync_and_journal_units_are_denied() {
        // Same split as the power-service test: miri sees one witness per
        // class, including the two stems that are not prefixes of each other.
        #[cfg(miri)]
        let security: &[&str] = &["nftables.service", "chronyd.service"];
        #[cfg(not(miri))]
        let security: &[&str] = &[
            "nftables.service",
            "ufw.service",
            "netfilter-persistent.service",
            "firewalld.service",
            "systemd-timesyncd.service",
            "dbus-org.freedesktop.timesync1.service",
            "chrony.service",
            "chronyd.service",
        ];
        for unit in security {
            assert!(
                classes("/usr/bin/systemctl", &["stop", unit])
                    .contains(&CapabilityClass::SecuritySubsystem),
                "{unit}"
            );
        }
        #[cfg(miri)]
        let journal: &[&str] = &[
            "systemd-journald.service",
            "systemd-journald-dev-log.socket",
        ];
        #[cfg(not(miri))]
        let journal: &[&str] = &[
            "systemd-journald.service",
            "systemd-journald.socket",
            "systemd-journald-dev-log.socket",
            "rsyslog.service",
            "syslog.socket",
        ];
        for unit in journal {
            assert!(
                classes("/usr/bin/systemctl", &["stop", unit])
                    .contains(&CapabilityClass::SelfModification),
                "{unit}"
            );
        }
        // `chronyd` is its own stem. Any continuation of `systemd-journald`
        // is the journal, including `-extra` and `-audit`. A name that does
        // not continue the stem is not. Miri already classified the service
        // and the dev-log socket.
        #[cfg(not(miri))]
        {
            assert_eq!(
                classes("/usr/bin/systemctl", &["stop", "chronyd.service"]).len(),
                1
            );
            for unit in [
                "systemd-journald",
                "systemd-journald-audit.socket",
                "systemd-journald-dev-log.socket",
                "systemd-journald@x.service",
                "systemd-journald-extra.service",
            ] {
                assert!(
                    classes("/usr/bin/systemctl", &["stop", unit])
                        .contains(&CapabilityClass::SelfModification),
                    "{unit}"
                );
            }
            assert!(!denies(
                "/usr/bin/systemctl",
                &["stop", "systemd-journaldctl.service"]
            ));
        }
    }

    #[test]
    fn denies_joined_config_file_option() {
        for arg in ["--config-file=/tmp/evil.conf", "-c/tmp/evil.conf"] {
            assert!(
                classes("/usr/bin/apt-get", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        // The near misses are the same check. Miri already ran the two
        // spellings above; the rest of the suite runs these.
        #[cfg(not(miri))]
        {
            assert!(
                !classes("/usr/bin/dnf", &["--config-file=/tmp/evil.repo"])
                    .contains(&CapabilityClass::ConfigNamedProgram),
                "dnf has no --config-file; that spelling is apt's"
            );
            assert!(
                classes("/usr/bin/dnf", &["--config=/tmp/evil.repo"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/apt-get", &["--config=/tmp/evil.conf"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/systemctl", &["-c/tmp/evil.conf"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
        }
    }

    #[test]
    fn denies_joined_package_option() {
        for arg in ["-oDir::Cache=/tmp/a0", "--option=Dir::Cache=/tmp/a0"] {
            assert!(
                classes("/usr/bin/apt-get", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        // Cluster and prefix checks are cheap under miri. A full argv check
        // is not, and coverage runs those below.
        assert!(short_cluster_has(b"-o", b"co"));
        assert!(short_cluster_has(b"-c", b"co"));
        assert!(!short_cluster_has(b"-y", b"co"));
        assert!(!short_cluster_has(b"-y/tmp/cache", b"co"));
        assert!(!short_cluster_has(b"--option", b"co"));
        assert!(!short_cluster_has(b"-", b"co"));
        assert!(!short_cluster_has(b"", b"co"));
        assert!(!short_cluster_has(b"-q", b"pf"));
        assert!(short_cluster_has(b"-f", b"pf"));
        assert!(long_option_is(b"--Config-File=/x", b"config-file", true));
        assert!(!long_option_is(b"--opt=x", b"option", true));
        assert!(!long_option_is(b"--Config", b"config", false));
        assert!(!long_option_prefix(b"--load-extra", b"load"));
        assert!(long_option_prefix(b"--loa=/x", b"load"));
        assert!(!long_option_prefix(b"--", b"load"));
        assert!(!long_option_prefix(b"--=x", b"load"));
        assert!(!long_option_is(b"-c", b"config", false));
        assert!(!long_option_prefix(b"load", b"load"));
        assert!(!ascii_eq_ignore_case(b"ab", b"a"));
        assert!(ascii_eq_ignore_case(b"Ab", b"aB"));
        assert!(!ascii_eq_ignore_case(b"Ab", b"ac"));
        #[cfg(not(miri))]
        {
            assert!(
                classes("/usr/bin/apt-get", &["-o", "Dir::Cache=/tmp/a0"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/apt-get", &[""]).contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/apt-get", &["-"]).contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/apt-get", &["--option-extra"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/usr/bin/apt-get", &["--opt=Dir::Cache=/tmp"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
        }
    }

    #[test]
    fn denies_joined_sysctl_load() {
        for arg in [
            "-p/tmp/evil.conf",
            "--load=/tmp/evil.conf",
            "--system=/tmp/evil.conf",
        ] {
            assert!(
                classes("/sbin/sysctl", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        // `-p` on systemctl is a property flag, not a file load.
        #[cfg(not(miri))]
        {
            assert!(
                !classes("/usr/bin/systemctl", &["-p/ActiveState"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
            assert!(
                !classes("/sbin/sysctl", &["--load-extra"])
                    .contains(&CapabilityClass::ConfigNamedProgram)
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_apt_config_file_case_variant() {
        for arg in ["--Config-File=/x", "--OPTION=Dir::Cache=/tmp", "--Option"] {
            assert!(
                classes("/usr/bin/apt-get", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        assert!(
            classes("/usr/bin/apt", &["--config-FILE=/x"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_apt_clustered_short_option() {
        for arg in ["-yc/tmp/x", "-soDir::Etc=/x"] {
            assert!(
                classes("/usr/bin/apt-get", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        assert!(
            !classes("/usr/bin/apt-get", &["-y"]).contains(&CapabilityClass::ConfigNamedProgram)
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_sysctl_f_alias() {
        for arg in ["-f", "-f/x", "-qp/x"] {
            assert!(
                classes("/sbin/sysctl", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
        assert!(!classes("/sbin/sysctl", &["-q"]).contains(&CapabilityClass::ConfigNamedProgram));
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_sysctl_abbreviated_load() {
        for arg in ["--l=/x", "--loa=/x", "--s", "--sys"] {
            assert!(
                classes("/sbin/sysctl", &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{arg}"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn denies_each_package_managers_own_config_options() {
        let rows = [
            ("/usr/bin/dnf", "--setopt=tsflags=nodocs"),
            ("/usr/bin/dnf", "-c"),
            ("/usr/bin/dnf", "-c/tmp/dnf.conf"),
            ("/usr/bin/dnf", "--conf=/tmp/dnf.conf"),
            ("/usr/bin/dnf", "--setop=tsflags=nodocs"),
            ("/usr/bin/dnf", "--installroot=/tmp/root"),
            (
                "/usr/bin/dnf",
                "--repofrompath=extra,https://example.test/repo",
            ),
            ("/usr/bin/yum", "--config=/tmp/yum.conf"),
            ("/usr/bin/yum", "-c/tmp/yum.conf"),
            ("/usr/bin/zypper", "--config=/tmp/zypp.conf"),
            ("/usr/bin/zypper", "-c/tmp/zypp.conf"),
            ("/usr/bin/zypper", "--root=/tmp/root"),
            ("/usr/bin/zypper", "--plus-repo=https://example.test/repo"),
            ("/usr/bin/pacman", "--hookdir=/tmp/hooks"),
            ("/usr/bin/pacman", "--hook=/tmp/hooks"),
            ("/usr/bin/pacman", "--config=/tmp/pacman.conf"),
            ("/usr/bin/pacman", "-c/tmp/pacman.conf"),
            ("/usr/bin/pacman", "--root=/tmp/root"),
            ("/usr/bin/pacman", "-r"),
            ("/usr/bin/pacman", "--dbpath=/tmp/db"),
            ("/usr/bin/pacman", "-b/tmp/db"),
            ("/usr/bin/pacman", "--sysroot=/tmp/root"),
            ("/usr/bin/dpkg", "--admindir=/tmp/adm"),
            ("/usr/bin/dpkg", "--instdir=/tmp/root"),
            ("/usr/bin/dpkg", "--root=/tmp/root"),
            ("/usr/bin/dpkg", "--pre-invoke=id"),
            ("/usr/bin/dpkg", "--post-invoke=id"),
            ("/usr/bin/dpkg", "--status-logger=id"),
            ("/usr/bin/dpkg", "--status-logge=id"),
            ("/usr/bin/dpkg", "--log=/tmp/dpkg.log"),
        ];
        for (exe, arg) in rows {
            assert!(
                classes(exe, &[arg]).contains(&CapabilityClass::ConfigNamedProgram),
                "{exe} {arg}"
            );
        }
        assert!(
            !classes("/usr/bin/dpkg", &["-oDir::Etc=/x"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        assert!(
            !classes("/usr/bin/dpkg", &["--list"]).contains(&CapabilityClass::ConfigNamedProgram)
        );
        assert!(
            !classes("/usr/bin/dnf", &["--color=auto"])
                .contains(&CapabilityClass::ConfigNamedProgram)
        );
        // `-c` on pacman is `--clean`/`--cascade`, not config. Refusing it is
        // what the short-cluster check does, and it is harmless.
        assert!(dnf_redirects_config(b"-c/tmp/dnf.conf"));
        assert!(pacman_redirects_config(b"-c"));
        assert!(!dpkg_redirects_config(b"--list"));
    }
}
