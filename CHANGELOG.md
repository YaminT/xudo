# Changelog

All notable changes to xudo are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- `xudo op remove-path <target>` removes a path under an `[[operation]]` rule
  through the password-authenticated gate. `--dry-run` lists the paths and
  removes nothing. A `harness` label on the rule is parsed and checked against
  the registry and is not a grant. Harness use of this operation is planned.
  The passwordless gate is not in this release.
- `xudo-session record <label>` and `void <label>`, the record helper an enrolled service's unit will run as root (`ExecStartPre=+`, `ExecStopPost=+`), in the new package `xudo-session-bin` (library logic in `xudod::unit_record`). A service harness has no scope xudo made: its cgroup is `xudo.slice/xudo-agent@<label>.service` and its record is `/run/xudo/sessions/svc-<label>`, which the cgroup attestor and the gate now accept beside `agent-<32 hex>`. The label in the unit name, the record and the registry entry must be the same, and a record with no deadline (`u64::MAX`) or a lifetime over 12 hours is accepted only under a `svc-<label>` name: an `agent-<32 hex>` scope record always expires within 12 hours of its creation, whatever its `way` says (a scope has no stop hook to void it). The helper refuses unless it is uid 0, its parent is pid 1, its own cgroup is exactly that unit under `xudo.slice` (root-owned, not group- or other-writable, populated), the registry has the label with `way = service`, and its account resolves in `/etc/passwd` to a non-zero uid; it also needs its user, pid, cgroup and mount namespaces to be pid 1's (the gate's check, reused); it replaces any old record by removing it and then publishing the new one (there is no record in between, so the unit is unattested and the gap fails closed), clears a stale `.tmp.svc-<label>` left by a crash first, and writes nothing it could not read back as attesting. `void` also needs parent pid 1, so H2c's `agent remove` must stop the unit and let its `ExecStopPost` void the record, not call the helper. A successful run no longer writes a blank stderr line. Tests `a_scope_name_with_the_service_way_and_no_deadline_is_refused`, `a_root_in_a_user_namespace_of_its_own_is_refused_by_both_verbs`, `a_host_with_no_proc_refuses_and_a_stale_temporary_record_is_cleared`. Nothing installs or runs it yet (packaging is a later step) and it grants no run: no caller skips the sudo password because of it.

- Packaging for enrolled agents, inert: `xudo.slice` (no `Delegate=`), the template `xudo-agent@.service` (`Slice=xudo.slice`, `Delegate=no`, `EnvironmentFile=-/etc/xudo/agents/%i.env`, `ExecStartPre=+` and `ExecStopPost=+` running `xudo-session record` and `void` for the instance name), tmpfiles rows for `/run/xudo/sessions` and `/run/xudo/rate` (`0700 root`), and `xudo-session` in the `.deb` as `/usr/libexec/xudo/xudo-session` (`0755 root`). The template has no `ExecStart=` and no `User=` (enrolment will write both into a drop-in), no credential, and no sandbox directive on purpose: sudo is setuid and the gate refuses a private mount namespace, so the boundary is the account's uid and the rules. `just units` exempts that one template, by name, from the exposure ceiling; `systemd-analyze verify` still applies to it in full. Nothing enables, starts or enrols anything, and no caller skips the sudo password because of this. `xudo-session record` also refuses unless `/etc/xudo/agents/<label>.env` is absent or a root-owned regular file (`lstat`, never followed) with no group or other permission bit, in a root-owned directory nobody else can write: systemd applies that file to the root `ExecStartPre=+` helper unchecked. The helper stays a static binary (the deb lane fails on a `PT_INTERP`), and the systemd lane removes the package while an `xudo-agent@t` instance runs and requires it stopped and its record gone. H2c must refuse a drop-in with no `User=` equal to the registry account (such a unit would run as root and still be attested), with a test. Tests `the_slice_delegates_nothing_and_sets_no_limit`, `the_agent_template_has_no_sandbox_directive_and_says_why`, `the_agent_template_runs_nothing_and_names_no_account`, `the_agent_template_records_and_voids_as_root_through_the_installed_helper`, `the_agent_template_uses_no_specifier_but_the_instance_name`, `the_agent_template_takes_credentials_only_from_an_optional_env_file`, `the_agent_template_is_placed_in_the_slice_and_cannot_delegate`, `the_package_ships_no_nopasswd_line_and_no_passwordless_gate`, `the_deb_installs_the_session_helper_as_root_only_writable_beside_the_broker`, `an_env_file_root_did_not_make_and_protect_is_refused_before_any_record`, `a_root_private_env_file_in_a_root_directory_is_accepted`, `an_env_file_that_cannot_be_inspected_refuses_the_record`.

- `xudo agent enrol <label> --account <name> --reviewer <name> [--dry-run] -- <program> [args]`, `xudo agent list` and `xudo agent remove <label>` (headless only; the account must already exist, `--create-account` is not built). `enrol` runs as root (through the machine's own `sudo`, which asks the password; xudo never sees it), prints the three files it will write and then writes them: the registry entry `/etc/xudo/harnesses.d/<label>.toml` (`way = "service"`), the drop-in `/etc/systemd/system/xudo-agent@<label>.service.d/10-xudo.conf` (`User=` and `ExecStart=`) and an empty `/etc/xudo/agents/<label>.env` (`0600 root`, kept if it exists), each starting with xudo's marker and renamed into place atomically; then `daemon-reload`, asks systemd for `User=` and stops unless it is the registry account, and enables the unit. A failure takes back everything this run wrote. It refuses uid or primary group 0, an account missing from `/etc/passwd` or named twice, a usable password (an empty or non-`!`/`*` field, or an unreadable `/etc/shadow`), the groups `sudo wheel root docker lxd incus libvirt disk shadow adm systemd-journal`, any other path to root found by the `doctor` scan with the account as subject (a passwordless sudo or doas rule, sudo's own listing for it, an unreadable sudoers file), the account as its own or another harness's reviewer, an account another label runs as or lists in `users`, a label already enrolled, and a drop-in directory that is not root's alone or already holds files (so no other drop-in can set `User=` after it). `ExecStart=` is written one-way: every word double-quoted, `\` and `"` escaped, `%` and `$` doubled, a control character refused, the program an absolute path. `remove` stops the unit (its `ExecStopPost` voids the record; the helper needs pid 1 as its parent, so `remove` never runs it), removes the drop-in and then the registry entry last, refuses an entry xudo did not write, and keeps the environment file (it may hold credentials). Enrolling grants nothing: no rule names the harness, so every command it asks for still asks for the sudo password. The shipped template `xudo-agent@.service` gains `[Install] WantedBy=multi-user.target` so `enable` has something to enable; nothing enables an instance on package install. Tests `enrol_refuses_an_account_with_a_usable_password`, `enrol_refuses_the_account_as_its_own_reviewer`, `enrol_refuses_an_account_with_any_sudo_rule`, `enrol_refuses_an_account_in_a_root_equivalent_group`, `enrol_refuses_an_account_used_by_another_label`, `enrol_refuses_a_drop_in_directory_that_could_override_user`, `a_drop_in_elsewhere_that_changes_user_stops_the_enrol`, `exec_start_escapes_specifiers`, `a_hostile_argument_cannot_leave_its_quotes`, `remove_stops_the_unit_first_and_deletes_the_registry_entry_last`.

### Changed

- An enrolled agent is confirmed unless a rule grants its harness: `confirm = "never"` no longer lifts the agent confirmation, only a rule that lists the agent's harness with `outcome = "allow"` does, and any stricter overlapping rule cancels it. A rule that lists a harness must now set `outcome` (no default; load error "a rule that lists a harness must set outcome"). The `confirm_agent_actions` engine setting is gone (the config key was already rejected). `Decision` gains the required field `harness_grant` (`ENVELOPE_SCHEMA_VERSION` stays 2: `deny_unknown_fields` makes a mixed client and broker fail closed) and the trace gains `harness_granted`; the agent confirmation reason text changed. A grant is recorded but the verdict still confirms, so `confirm_human_path` is not lifted. The grant opens no passwordless path: every command still asks the sudo password.
- Ask-human rules now use denial code `ask_human` and send a verified, explicitly listed harness request to the broker's root-held queue by default. The queue stores byte-exact argv and cwd, enforces per-uid and global bounds, uses boottime expiry, and returns entries only to their owner for status or to a Human-classified configured reviewer. Human-path denials are no longer written into the caller-owned `ido` queue. A human reviewer runs a queued entry with `xudo exec --queued ID`: the broker re-decides the stored argv, the password gate runs it in `/`, and the entry is completed only from that gate's audit record. `ido` lists the root-held queue separately from the agent-editable user queue. The passwordless gate is not in this release.
- `ido list --json` always prints one JSON object with `user` (the previous user-queue array), `root_held`, and `root_queue_unavailable`, including when the root-held list is empty.

### Security

- A service record is attested only for the unit it names: a record `svc-codex` in the unit `xudo-agent@claude.service`, a `.scope` spelled like a service, a unit outside `xudo.slice` and a unit under the slice with no record all stay unattested, and a stale record no longer attests once its registry entry changes. The record helper refuses to write one for any cgroup but its own. Tests `a_record_for_one_label_in_another_labels_unit_is_refused`, `the_record_helper_refuses_outside_its_own_unit`, `the_record_helper_refuses_when_not_started_by_pid_1`, `the_record_helper_refuses_a_label_with_no_service_entry`, `a_user_manager_unit_named_like_the_harness_is_not_one`, `a_unit_under_the_slice_without_a_record_is_unattested`, `a_session_record_with_no_deadline_is_refused`, `a_service_restart_gets_a_fresh_record`.
- The broker has one way to classify a live peer, `classify_with_registry`, against the registry loaded for that very request. `stored_caller` also builds a class, from a spool entry and with no registry; it only selects which rules apply when a human answers and never grants a harness anything (test `stored_caller_is_never_a_live_attestation`). The one-entry-point refactor defers handing `identify_classified(registry)` one policy snapshot: each handler classifies and decides against one snapshot, a registry change in between only withholds (the entry hash no longer matches), and the passwordless gate must mint from that same caller/policy pair, never from `stored_caller`. The empty-registry `classify` is gone (its tests use `classify_for_test`), and the kernel fact `CgroupAttestation::AgentScope` is renamed `UnregisteredScope`: a live agent scope names no harness until the registry says so. The `freeze` audit record and the `queue_listed` record named every caller `human`; they now record the class the broker attested (an unattested caller was logged as a human). No caller skips the password. Tests `an_unregistered_scope_is_never_a_harness_in_any_handler` (every `Question`), `a_real_harness_cannot_freeze`, `the_audit_names_the_class_the_broker_attested_not_human`.
- Dangerous harness rule shapes now fail at load (the deny-list version 8 in the snapshots comes from the multicall fix on main, not this change), so the broker and the gate refuse to arm them, not only `xudo check`: a rule that lists a harness may not use a `path-under` or `pattern` matcher, set `agent-allowed = false`, or run a program on the vendored GTFOBins list (matched by basename and name stem, so `python3.12` counts; `deny.rs` is the backstop for copies and renames) unless the rule carries `gtfobins-waiver = "<technique>: <why>"` (20 and 80 characters at least; part of the ruleset generation; an error where it waives nothing). The near-miss lint now needs a `deny` test pinned to the action that differs in exactly one operand from one of its own allow or confirm tests and that the matcher rejects; it stays a `check` error, not a load error. `harness_lints` no longer takes the GTFOBins waiver list (`ci/gtfobins-waivers.txt` still governs shipped rules). No caller skips the password. Tests `a_harness_rule_with_path_under_fails_to_load`, `a_harness_rule_with_pattern_fails_to_load`, `a_harness_rule_that_is_human_only_fails_to_load`, `a_harness_rule_on_a_gtfobin_without_waiver_fails_to_load`, `a_thin_or_misplaced_gtfobins_waiver_fails_to_load`, `a_deny_test_for_another_shape_is_not_a_near_miss`, `a_near_miss_differs_in_exactly_one_operand`, `a_waiver_is_part_of_the_generation`.
- A harness registry that fails the trust walk or does not parse no longer refuses every request, humans included. It yields an empty registry and a `registry_fault`: the rules load, the human path is unchanged, and every harness is disarmed. Removing a registry file disarms its harness the same way. A rule naming an unregistered label loads and grants nothing (it was a load error); `xudo check` reports it, and the fault, as a harness lint error (exit 21). While the registry is faulted a non-root `xudo thaw` is refused for every uid, since none can be ruled out as an agent's. `/etc/passwd` is still read lossily; `passwd_uid` now skips a line whose uid does not parse and takes the next one for the name, as glibc does, and a `passwd_fault` counts unusable and non-UTF-8 lines. Both faults are in the evidence of every gate and broker decision record and in `xudo doctor` (text and JSON). `/etc/passwd` only, no NSS. Tests `a_bad_registry_file_keeps_the_human_path_and_grants_nothing`, `removing_a_registry_file_makes_its_harness_human`, `a_rule_naming_an_unregistered_label_grants_nothing`, `a_non_utf8_passwd_line_is_reported_not_silent`, `passwd_skips_a_line_with_an_unparsable_uid_like_glibc`, `a_thaw_is_refused_to_every_non_root_uid_while_the_registry_is_faulted`, `a_registry_fault_is_in_the_evidence_of_every_gate_record`, `a_decision_record_carries_the_registry_and_passwd_faults`, `check_refuses_a_rule_naming_an_unregistered_harness_and_a_faulted_registry`. Also repairs the `harness_grant` snapshots, which still pinned deny-list v7.
- A rule for a multicall program (`coreutils`, `toybox`) whose applet argument is not pinned is now a `xudo check` lint error (exit 21): the self-denying check no longer flags `coreutils` (it only refuses an applet-less argv), so an open applet matcher would otherwise pass every gate. The deny-list (version 8) now also refuses, through a multicall, `sort`/`shuf` with an output file, `sort --compress-program`/`--files0-from`, `uniq` with two operands, `date -f`/`-s`, `ptx`, `csplit`, `runcon` and `kill`. Tests `a_coreutils_rule_with_an_unpinned_applet_is_flagged`, `a_coreutils_rule_pinning_a_safe_applet_is_not_flagged`, `a_one_of_with_a_dangerous_applet_is_flagged`, `denies_coreutils_sort_output_to_a_root_file`, `denies_coreutils_shuf_output`, `denies_coreutils_runcon`, `denies_coreutils_kill_of_pid_one`, `appending_an_argument_to_a_multicall_applet_never_allows`, `no_shipped_rule_exposes_an_unpinned_multicall_applet`, `check_rejects_an_unpinned_multicall_applet`.

- The gate now reads its own facts instead of the spool entry's. It reads the matched ancestor's uid from that process's live `/proc/<pid>/status` (the real uid, since the pinned `xudo` has exec'd the setuid `sudo`, and the process must still be the pinned `(pid, starttime)`), and refuses the run (`request_wrong_caller_uid`, high severity) when it is not the uid the entry was minted for or cannot be read; the live uid, not the entry's, now picks the freeze marker. The ancestor and the gate itself must also be in PID 1's user, pid, cgroup and mount namespaces (inodes compared through the pinned procfs descriptor and proven to be on nsfs), have one `NSpid` level and the identity `uid_map`; any difference or failed read makes the caller unattested, so a mount namespace made before `sudo` cannot show the gate a different host. The effective class is the live class only when it equals the broker's record, otherwise `Unattested` (never an upgrade, never a relabel), and a queued run (`xudo exec --queued`) needs an effective `Human`; one that does not is refused with its own code, `request_queue_needs_attested_human`, distinct from `request_queue_not_claimed` (a human whose session is in another mount namespace, via `pam_namespace` or a snap, gets it on `ido` and `xudo exec --queued`; the password path still runs). The trust boundary is PID 1 of the pid namespace of the pinned `/proc`: "PID 1's namespaces" means that init's. On a normal host that is the host's. Inside a container, or a setuid sandbox with its own pid and mount namespaces and a fresh `/proc` (firejail), the checks compare against that namespace's init and pass; containers are not a supported deployment, no upgrade was found there (cgroup membership does not change and an unprivileged user cannot build that layout without a setuid helper), and a stricter check would compare the fixed init inodes (user `0xEFFFFFFD`, pid `0xEFFFFFFC`, cgroup `0xEFFFFFFB`). `xudo-sys` gains `ProcSource::namespace_inode`, `MapSource::with_inode` and the shared `parse_nspid_count`, `is_identity_uid_map` (moved from `xudod`). No caller skips the password. Tests `the_gate_refuses_an_ancestor_in_another_user_namespace`, `the_gate_refuses_an_ancestor_in_another_mount_namespace`, `the_gate_refuses_an_ancestor_in_another_pid_or_cgroup_namespace`, `the_gate_refuses_when_it_is_itself_in_another_mount_namespace`, `an_ancestor_with_a_nested_pid_or_mapped_uid_namespace_is_unattested`, `the_gate_reads_the_uid_from_the_live_ancestor`, `a_spool_uid_that_differs_from_the_live_one_is_refused`, `an_ancestor_whose_uid_cannot_be_read_is_refused_not_trusted_from_the_entry`, `a_setuid_sudo_ancestor_reads_as_its_real_uid`, `a_stored_unattested_entry_is_never_human_at_the_gate`, `a_live_unattested_read_downgrades_a_human_entry`, `a_pid_reused_between_the_reads_yields_nothing`, `a_pinned_non_root_process_that_execs_sudo_is_read_as_its_real_uid` (root lane).
- A harness registry whose reviewer is the account or a user of any harness (its own or another's) now fails to load. Such a reviewer could approve what its own agent queued. Tests `a_reviewer_that_is_a_harness_account_fails_to_load`, `a_reviewer_that_is_a_harness_user_fails_to_load`, `a_reviewer_overlapping_another_harness_fails_to_load`, `disjoint_reviewers_load_across_harnesses`. The error names the harness that owns the clashing account. The queue also compares uids at request time, so a reviewer who shares a uid with a harness account under another name is refused (`an_alias_reviewer_with_a_harness_accounts_uid_is_refused`, `a_reviewer_with_a_distinct_uid_is_still_allowed`).
- `xudo freeze` and `xudo thaw` now classify the caller against the real harness registry. They used an empty one, so an enrolled agent counted as unattested and could lift its owner's freeze. Tests `an_enrolled_agent_cannot_thaw_its_owners_freeze_through_the_broker`, `an_enrolled_agent_cannot_freeze_or_thaw_others`.
- A non-root `xudo thaw` is now refused for an unattested caller and for any caller whose uid is the account or a user of any registered harness (`ChannelUntrusted`, "use `sudo xudo thaw`"). "Outside any agent scope" is not "a human": an agent can start a process outside its scope as its own uid, so only root, or `sudo xudo thaw` (uid 0, which the password already proved), lifts a harness uid's freeze. A user who is not a harness uid still thaws only their own marker. A password-proof thaw for ordinary users arrives with the passwordless-gate work. Tests `an_outside_caller_with_a_session_harness_uid_cannot_thaw`, `a_service_harness_account_cannot_thaw_even_outside_its_scope`, `a_harness_uid_alias_cannot_thaw`, `a_user_who_is_not_a_harness_uid_still_thaws_their_own_marker`, `root_can_thaw_any_marker`, `an_unattested_caller_cannot_thaw`. Freeze is unchanged (it only withholds). Freeze and thaw refuse when `/etc/passwd` is missing or empty, and the policy load fails closed the same way: only an EMPTY or unreadable `/etc/passwd` stops every xudo request (which only withholds, and root can still `touch /var/lib/xudo/frozen`). Stray non-UTF-8 bytes are read lossily, because any user can put one in their own GECOS with `chfn`; the name and uid fields are ASCII-validated and only root edits uids, so such a byte cannot change who resolves to which uid, and a bad line is never skipped (`an_empty_passwd_refuses_freeze_and_thaw`, `an_empty_passwd_still_fails_the_load_closed`, `a_non_utf8_gecos_does_not_stop_the_policy_load`, `a_harness_user_with_a_non_utf8_gecos_is_still_refused_a_thaw`, `a_non_utf8_byte_cannot_change_a_name_or_uid_field`). The refusal says `sudo xudo thaw` lifts ALL freezes. A broken registry also locks the human out of freeze; that is acceptable because nothing runs while the policy fails to load.
- The doas rule `xudo install` writes no longer says `persist`: an OpenDoas built with timestamp support could let a long-lived caller reuse one password. Test `doas_snippet_never_enables_credential_persistence`.
- `xudo doctor` flags a doas rule that comes after xudo's own and names the xudo group or the gate (doas uses the last matching rule), with its file and line, and says when it carries `persist` or `nopass` (`flags_a_doas_conf_dropin_that_sorts_after_xudos_and_restores_persist`, `flags_a_rule_appended_after_xudos_block_with_nopass`). Not done: naming the drop-in so it sorts last.
- The doas later-rule check in `xudo doctor` now reads rules the way OpenDoas does: `#` ends the line and a word, `{` and `}` are words of their own, identities resolve by name or number through `/etc/passwd` and `/etc/group` (supplementary and primary groups), `as <other user>` rules are not counted, and a name it cannot resolve leaves the check unverified. A later `deny` is a note. Only `*.conf` files of `/etc/doas.d` are read, as doas does. Tests `a_hash_ends_the_word_in_a_later_rule`, `a_cmd_inside_a_comment_does_not_limit_the_rule`, `a_setenv_brace_is_its_own_token`, `a_numeric_uid_identity_is_resolved`, `group_membership_by_supplementary_group_is_resolved`, `primary_gid_membership_is_resolved`, `a_later_rule_for_another_target_is_not_flagged`, `a_later_deny_is_a_note_not_a_weakening`, `doas_reads_only_conf_files_of_its_drop_in_directory`.
- `xudo install` on doas refuses (exit 19) when a rule after xudo's own carries `nopass` for the xudo group, and warns for `persist`. It only sees xudo's rule once installed, so the first install is checked by `xudo doctor` afterwards. Test `install_refuses_a_later_doas_rule_that_takes_the_password_from_the_gate`.
- A capability marked exempt without a recorded reason is still missing (`an_exemption_without_a_recorded_reason_is_still_missing`).
- doas no longer claims the pty control from a parse check. `xudo doctor` reports it as an explicit exemption ("doas never allocates a pty; accepted because the target is root") and the credential cache as unknown, not absent. The doctor JSON capability rows gain `exempt` and `unknown`.
- A queued claim records the reviewer uid and a claim token. Another reviewer cannot release, fail, or complete a fresh claim; after 15 minutes they may recover a stale claim, and only if the audit trail has no gate record for that nonce. A release or failure revokes the minted spool entry. The gate refuses a queued run whose queue record is not currently claimed for that nonce. Completion searches a bounded tail of the audit log under the log lock.
- Let the broker read `/proc/sys/kernel/random/boot_id` by removing
  `ProcSubset=pid` from its unit. Keep `ProtectKernelTunables=yes`; the unit
  remains at the configured 1.2 systemd exposure ceiling. Use the same strict
  lowercase boot-id validator in the syscall seam and broker paths.

- Reset every resource limit from PID 1 before the gate reads policy, consumes
  a request, writes an audit record, or runs a command. Cap the soft open-file
  limit at 1024 and disable core dumps. In a container or PID namespace, PID 1
  is that namespace's init, and using its limits is acceptable. The refusal
  record after a failed reset is still written under caller limits; CPU time or
  signals can tear that one record. Blocking signals around audit append and
  cut-back remains unavailable through a safe API.
- Bound the macOS `cross` and `gate` CI jobs to eight minutes; Ubuntu gate
  jobs retain their existing timeout and no retries were added.
- Ship active `00-protect.toml` rules that refuse removal of xudo, sudo,
  sudo-rs, AppArmor, audit, firewall, logging, time-sync, and SSH server
  packages through the shipped `apt-get remove` action. Its other clauses are
  tripwires for broader operator actions. The policy loader still rejects deny
  rules for programs with no loaded action, so apt and dpkg tripwires are tested
  with broad test-only operator actions until those executables have shipped actions.
- Protect `/usr/bin/xudo`, `/usr/bin/ido`, and `/usr/libexec/xudo/xudod` from
  xudo-mediated writes; bump the compiled deny-list version to 7.

- `path-under` is lexical only. Nothing in xudo enforces containment for
  argument paths. Never use it for a program that opens the path as root.
  A rule that allowlists `rm` of a home directory accepts a path the agent
  planted as a symlink and deletes whatever that symlink points at. The
  compiled-in deny-list now refuses that class of tool
  (`ChangesPathMetadataOrExistence`, deny-list version 7): `rm`, `rmdir`,
  `unlink`, `chmod`, `chown`, `chgrp`, `chattr`, `setfacl`, `setfattr`,
  `touch`, `mkdir`, `mkfifo`, `rename`, and `prename`, including a copy or
  hardlink that keeps the name and a `busybox` applet. `mknod` joins
  `DeviceOrFilesystem`. `setcap` was already `PrivilegeTool`. `mount` and
  `umount` are not named on the list. `xudo check` warns on every
  `path-under` matcher and exits 20. A rule that allowlists one of these
  tools is a lint error, as with any other deny-listed executable.

## 0.1.0-beta.2 - 2026-11-16

### Security

- v0.1.0-beta.1 accepted `systemctl` start, stop, and restart of power,
  reboot, rescue, kernel-module, filesystem-template, and broker-socket
  units for any caller who could pass the password gate. The filesystem
  templates on the deny-list are `systemd-fsck@`, `systemd-growfs@`,
  `systemd-makefs@`, and `mdadm*@`. A `.mount` unit is not on that list, and
  `unit-name` accepts it. The tripwire is a name list: an alias or a unit
  that is not enumerated gets past, and the enumeration is the boundary.
  The shipped rule set no longer contains a service lifecycle rule. Copy
  `/usr/share/xudo/examples/20-services-lifecycle.toml` to
  `/etc/xudo/rules.d/` and list the units that host should expose.
  `xudo check` and `xudo doctor` note the omission. The compiled-in deny-list
  still refuses those names, plus the systemd power and sleep services,
  `debug-shell`, runlevel aliases, firewall and time-sync units, and the
  journal units, on a verb that starts, stops, signals, or otherwise acts,
  including when an operator's rule names one of them. A read-only verb is
  not refused because of the unit name.
  If dpkg asked about `/etc/xudo/rules.d/20-services.toml` during the
  upgrade and you kept your version, you still have the beta.1 rule: run
  `xudo check`, and replace its `unit-name` with a `one-of` list of your
  units. `xudo check` exits 21 for that rule, and `xudo doctor` prints the
  same sentence. On an upgrade from a version below `0.1.0~beta.2` the
  package says to check that file with `xudo check`. It does not decide
  whether the host is exposed. `xudo check` and `xudo doctor` both report
  those rows as `open_unit_lints` (`check` nests the array under `lint`).
- `systemctl poweroff`, `reboot`, `halt`, `kexec`, `suspend`, `hibernate`,
  `hybrid-sleep`, `suspend-then-hibernate`, `soft-reboot`, `sleep`, `rescue`,
  `emergency`, `default`, and `exit` are refused with any arguments.
  `isolate` is refused for every target, including `start --job-mode=isolate`,
  the split form `--job-mode isolate`, and a getopt prefix such as
  `--j=isolate`. `systemd-exit.service` is refused
  with the other power services: its unit file sets `SuccessAction=exit-force`.
  An option value cannot hide the verb: `-p`, `-M`, `--when`, `--message`,
  and the other options that take the next argument are scanned like every
  other token. The read-only exemption is a whitelist of one shape: optional
  no-value flags (`--no-pager`, `--full`, `--no-ask-password`, `-l`,
  `--no-legend`, `--plain`, `--value`, `--all`), a read-only verb, then only
  unit names or joined `--property=` flags. Any other option, or any verb of
  the non-read-only set (including `reenable`, `reset-failed`), removes it
  and the full check applies to every token. `*`, `?` and `[` in a token
  outside that shape, and `-H`, `--host`, `-M`, `--machine` and their
  prefixes, are refused. `status rescue` is refused,
  because `rescue` is a power subcommand. `status rescue.service` still reads.
- The acting verbs also include `kill`, `clean`, `freeze`, `thaw`, and the
  compatibility names `condrestart`, `force-reload`, `reload-or-try-restart`,
  `condreload`, and `condstop`. Stock Debian 13 and Ubuntu images used for
  the check do not ship `systemctl`, so those names were not confirmed with
  `--help`. A verb systemd would reject is still refused.
- The tripwire is best effort for operator rules and covers the `systemctl`
  program only. A rule whose exe is not exactly `systemctl` gets no checks
  and no lint. `service`, `invoke-rc.d`, `busctl`, and a unit alias such as
  firewalld's `dbus-org.fedoraproject.FirewallD1.service` get around it. The
  enumeration is the boundary. `xudo check` also reports an enumerated unit
  list that names a refused unit or a glob. The set of non-read-only verbs
  is from the systemd 257 verb table and was not checked against a binary.
- `systemd-journald` followed by `-`, `.`, or `@` is the journal for any
  continuation. `systemd-journald-audit.socket` was not refused.
- Read-only `systemctl` verbs (`status`, `show`, `is-active`, `is-failed`,
  `is-enabled`, `cat`, and the `list-*` queries) are not refused just
  because the unit is on the tripwire. Nothing changed for diagnostics:
  `xudo.svc.status` and `xudo.svc.show` of `xudod`, the journal, chrony,
  nftables, apparmor, and auditd still run. A verb that starts, stops, or
  signals the unit is still refused, and a power subcommand is still refused.
- The unit name list also refuses `umount.target`, `final.target`,
  `rescue.service`, `emergency.service`, `syslog.socket`, the timesyncd
  alias `dbus-org.freedesktop.timesync1.service`, `systemd-repart.service`,
  and `systemd-sysctl.service`. Each of those exists on Debian 13, Ubuntu
  24.04, or Ubuntu 26.04 (`systemd-repart` only on Ubuntu 24.04).
  `systemd-sysctl` applies sysctl files at boot and uses the same class as
  a file-driven sysctl flag. `systemd-tmpfiles-*` and `logrotate.service`
  were left off: they run programs whose names are already refused.
  `syslog.service`, `ntp.service`, `ntpsec.service`, `iptables.service`,
  `systemd-mkswap@`, and `systemd-cryptsetup@` had no unit file on those
  three images.
- Package-manager config redirects are matched per tool. apt long options
  are case-insensitive and a short cluster is scanned for `c` or `o`.
  sysctl also refuses `-f` and a prefix of `--load` or `--system`. dnf
  and yum refuse `-c` (their short form of `--config`) and a prefix of
  `--config`, `--setopt`, `--installroot`, or `--repofrompath`. pacman
  refuses a prefix of `--config`, `--hookdir`, `--root`, `--dbpath`, or
  `--sysroot`, and the short options `-c`, `-r`, and `-b`. pacman's `-c`
  is `--clean` or `--cascade`, not a config file; refusing it is harmless.
  zypper refuses `--root` and `--plus-repo`. dpkg refuses a prefix of
  `--status-logger` (it runs a command) and `--log`. dnf, yum, pacman, and
  zypper were not installed on the images used for the check. This is
  defence in depth: the shipped rules still only name apt-get, and their
  positions are literals.
- The install rule accepted a package name ending in `-` (`apparmor-`),
  which `apt-get install` reads as a request to remove that package, skipping
  the confirmation the remove rule demands when `confirm_human_path` is on. `deb-name` and `apk-name` now
  reject a trailing `-`. The install rule also requires `--no-remove`, so an
  install that would remove a conflicting package is refused; the operator
  removes that package with the remove rule. A trailing `+` stays accepted
  by `deb-name`: `g++` and `libstdc++6` are real names, and `pkg+` on
  `apt-get install` is harmless.
- apt-get reads a package name containing `.` or `+` that is not an exact
  cache hit as an unanchored regular expression. On install that can select
  many packages and cannot remove one, because the install rule requires
  `--no-remove`, so `deb-name` is unchanged there.
  `APT::Cmd::Pattern-Only=true` would turn that regular expression off, but
  the deny-list refuses `-o` and apt ignores an unknown key, so it is only
  a possible later defence in depth. On remove one confirmed
  token such as `lib.` or `libstdc++` could remove hundreds of packages
  (`+` is a regular expression character too), and a trailing `+` on remove
  installs. The remove rule now uses `deb-name-literal` (`deb-name`, and
  no `.` and no `+` anywhere). A package whose name contains either
  (`python3.12`, `g++`, `libstdc++6`) can no longer be removed through xudo.
  Remove it with the host's own tools, or add an operator rule that lists
  that name with `one-of`. The ruleset generation changes, so an approval
  already minted is no longer valid.
- The audit appender wrote a record with `write_all`. A caller who set
  `RLIMIT_FSIZE` just past the log made the first `write` return a short
  count and the next one raise `SIGXFSZ`, which killed the gate before the
  torn tail could be cut back. The broker and every later gate then refused
  the damaged log. An append is now one `write`. On this `RLIMIT_FSIZE`
  route a short count is a failure and the existing cut-back runs, so the
  request is denied and the log stays intact. `EINTR` (which writes nothing)
  is tried once more; a second interrupt is a failure too. This holds for
  `RLIMIT_FSIZE` only. `SIGXFSZ` and `SIGXCPU` are core-dump signals and are
  not delivered between the pages of one `write`, so they do not tear a
  record. `SIGTERM`, `SIGHUP` and `SIGINT` still can, when the record crosses
  a page boundary; the caller can steer that length through argv, and sudo
  relaying a signal (or the pty hanging up) can deliver it. That route
  predates this fix. xudo stays down until an operator moves the log aside.
  Blocking signals around the write is a later change. When the gate's own
  append fails because the log is damaged or the cut-back did not land, it
  prints one fixed line on stderr telling the operator to move the log
  aside. The line has no path and no bytes from the log. The exit status
  is unchanged. The broker's refusal message still carries the error text.
- sudo-rs 0.2.5 and OpenDoas pass a caller umask of `000` through to the
  root command. Classic sudo applies `022`. Measured. A file an apt hook or
  a maintainer script creates would then be world-writable. The gate now
  always sets umask `022`, and the command starts in `/`. sudo's own rule
  is the caller's umask combined with `022`, so a caller's `077` is now
  loosened to `022`. `027` would make files root writes under `/etc` and
  `/usr` unreadable to non-root daemons, and keeping sudo's combined rule
  would let a tight caller umask under sudo-rs or doas do the same to other
  users' services. A fixed `022` is deterministic and matches what classic
  sudo gives.
- In the default configuration (`confirm_human_path` off),
  `xudo.pkg.remove`'s `confirm = "always"` is satisfied by the password
  alone. A member of the `xudo` group who passes the password can remove
  packages through it, including xudo, sudo, apparmor, auditd, nftables, ufw
  and rsyslog. This was already true in beta.1 and is not changed here; a
  package-name tripwire for those is a later change.
- The shipped `timedatectl set-ntp false` has the same effect as stopping
  the time-sync unit, which the tripwire refuses for operator rules.

### Added

- Executable `[[test]]` tables in rule files, run by `xudo check` and by the
  build. A test never changes a decision and is not part of the ruleset
  generation.
- `xudo check --fuzz [--fuzz-budget N] [--fuzz-seed S]`: a bounded,
  deterministic differential fuzz of the loaded ruleset that cross-checks the
  overlap report and the standing invariants; a finding is a lint error (21).
- `xudo config` (`get`, `list`, `schema`) shows the effective configuration
  and the file and line each value came from. `ido config list` shows ido's
  user layer.
- `xudo exec --queue`: a request refused only because it needs the human path
  goes into the caller's `ido` queue. It runs nothing and keeps the denial's
  exit status.
- `ido queue --root` marks an entry to run through `xudo exec`, with policy,
  audit and the password prompt, and so does every entry `xudo exec --queue`
  writes. `ido run --yes` refuses a root-marked entry. The queue format and
  the `AGENTS.md` / `xudo agentdoc` block are now version 2.
- Release engineering: the binaries embed their dependency list
  (cargo-auditable), each release ships a signed CycloneDX SBOM, CI rebuilds
  each package on a second runner and requires matching bytes before signing,
  and cargo-vet is part of the supply-chain checks.

### Changed

- **Breaking:** the shipped argv and rules changed. The service-lifecycle
  rule no longer ships: copy `/usr/share/xudo/examples/20-services-lifecycle.toml`
  to `/etc/xudo/rules.d/` and list your units. `xudo.pkg.install` now
  requires `--no-remove` before the verb, and the old argv is denied.
  `xudo.pkg.remove` refuses names containing `.` or `+`. `reset-failed` takes
  only a plain `.service` and is refused for the tripwire units (journald,
  apparmor, chrony and others). The gate now starts the root command with
  umask 022 and cwd `/`. Re-run `xudo agentdoc`, and drop queued `ido`
  entries that use the old argv.
- A kept or edited beta.1 `/etc/xudo/rules.d/30-packages.toml` still has the
  old rule text. The compiled-in refusal of a trailing `-` applies to it, but
  `--no-remove` and the literal-name rule do not, and no lint catches it.
  Compare it with the new file (`xudo doctor` shows it as changed locally).
- **Breaking:** `xudo check` exit codes. Overlapping actions now exit 20 (was
  0), the shell-allowlist lint exits 21 (was 17), and a failing rule test exits
  22. A failing test ranks above a lint error when one run finds both.
- The ruleset generation is hashed from a canonical encoding of each action
  (framing v2), and a rule file with no actions is no longer part of it. Every
  approval in flight when xudo is upgraded is invalidated once; retry the
  request.
- A rule file may carry at most 4096 `[[test]]` tables, and a ruleset at most
  16384 in all; more fails to load.
- The doas rule `xudo install` writes uses `permit persist`. On an OpenDoas
  built with timestamp support, one password then covers about five minutes
  of `xudo exec`, unlike the sudo rule, which sets `timestamp_timeout=0`. The
  package depends on sudo.

### Compatibility

- The shipped rules carry `[[test]]` tables, which a 0.1.0-beta.1 binary
  rejects as an unknown key. Downgrading xudo below this version while keeping
  the new rules denies everything until the rules are downgraded with it.

## 0.1.0-beta.1 - 2026-11-10

### Added

- M3 out-of-band confirmation through `xudo watch`, including pending
  requests, freeze and thaw controls, and per-user and global watch quotas.
- Strict wire-message parsing and a journald-only `audit_sink` setting.
- Linux command-line policy inspection, rule checking, configuration schema,
  host diagnostics, audit verification, and agent documentation generation.
- A root broker, a password-authenticated gate, a one-use request flow, and a
  tamper-evident authorization audit trail.
- A single Debian package for xudo and ido, with a systemd socket-activated
  broker and password-only sudo integration.
- Container coverage for package install, upgrade, removal, purge, and the
  installed password and gate path on Debian 13, Ubuntu 24.04, and Ubuntu 26.04.
- Pasban's daily root timer verifies the audit chain and compares the file with
  journald copies by hash. It detects removed tails, cut-and-continued files,
  and forged chains the journal did not observe. It does not prevent root from
  changing both sources or record command outcomes.

### Security

- Human confirmation is disabled by default (`confirm_human_path=false`); every
  request continues to use the host password path.
- `just telemetry` runs the strace no-telemetry check, also run by the CI job
  "no telemetry".
- Every request uses the human password path. Out-of-band confirmation through
  `xudo watch` is built and off by default. The passwordless agent path and
  Landlock confinement are not in this beta.
- No release has been published. The release workflow signs the package with
  cosign keyless signing when a version tag is pushed.
- Install probe reports `installed, but NOT VERIFIED` on doas and on a
  multicall-coreutils system with no regular probe program, such as Alpine.
- The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a
  regular file, so stock Ubuntu 26.04 verifies.
- The audit trail records authorization, not outcomes.
