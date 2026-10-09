# Follow-up review — 8 October 2026

A second review of the sources released as **10.5.7.0 / Manager 2.3.1** (starting revision
`b1ac978bd`), made after [the first audit](AUDIT-2026-10-08.md) of the same day. The
corrections are on branch `bughunt-2026-10-08` as **Manager 2.3.2** and the next product build.
They are **not released**: installer, native and elevated checks run only in CI (see
[Verification](#verification)).

## Method

1. Seven reviewers read one area each (partners and SFTP, key formats, agent and alerts,
   configuration and recovery, client workspace, server window, installer and native patch) and
   reported about 95 candidate defects with a concrete failure scenario.
2. Each candidate went to a verifier told to refute it by reading the actual code paths. Medium
   and high survivors got a second, independent check that also judged the proposed fix. 74 of 75
   were confirmed (several at a lower severity), one stayed uncertain (P14) and one was refuted
   (A8: timestamps written with `"o"` do parse correctly under th-TH).
3. Some claims were checked on a real installation, read-only: the owner PID of an established
   SSH connection, the size and XPath behaviour of the OpenSSH event log, and date formatting and
   parsing under the Thai Buddhist calendar on .NET Framework.
4. The fixes were made in seven isolated worktrees with disjoint file ownership. Each branch was
   reviewed adversarially, repaired, and merged. The merged branch was reviewed again by area and
   for semantic merge conflicts.

## Highest-impact findings

| ID | Severity | Finding | Consequence | Correction |
|---|---|---|---|---|
| R14 | High | Automatic blocking looked for user sessions among the children of the TCP owner of each connection. On Windows that owner is always the listening `sshd.exe`; the account's `sshd-session.exe` is a grandchild. | The "never block an address with a logged-in session" rule never matched, and the Block dialog never warned that it would lock out a connected administrator. | A session's address is the `Accepted ... from <address> port <n>` login its monitor recorded, while that connection is still open; logins are kept by process id and start time because the 1 MB circular log overwrites them. Unknown sessions defer blocking. |
| R6 | High | A failed read of the firewall block rule counted as "nothing blocked"; the agent and the Block dialog then wrote the rule back with only the new addresses. | One transient COM error could unblock every blocked address, manual blocks included. | Only "not found" means no rule; any other failure defers and is shown in agent health. Additions re-read and merge immediately before writing. |
| R2 | High | The authorized_keys parser ignored quotes: `command="exec ssh-agent bash"` made `bash` the key. | Removing one such key removed every line with the same fake blob; adding a second was skipped as a duplicate. | Options and key are found as `sshd` finds them (quoted option field, `rsa-sha2-*` names, `\v\f\r` inside the key). |
| R9 | High | Partner setup rewrote the global login methods from the main file's defaults, above any `Include`. | `PasswordAuthentication no` or `AuthenticationMethods` in an included file was overridden for every account. | Partner setup writes its rules only. |
| R12, D1, D8 | High | A new partner silently took over an existing `<root>\<name>` folder, keeping its owner and permissions. | An outside party could receive another company's files, and whoever pre-created the folder kept control of the partner's uploads. | Creation refuses an existing folder; reuse after deleting a partner asks first and resets the folder to Administrators/SYSTEM plus the partner, refusing links. New folders are created Administrators-only before the account exists. |
| R11 | Medium | Keys left in `partner_keys` by an earlier account of the same name were kept. | The previous company's key logged in to the new account. | Stale keys move to `partner_keys.removed`; partner key writes keep no `.bak` that `%u` could resolve. |
| G1 | Medium | The setup wizard took its port from the main file only and narrowed the firewall rule to it. | With `Port` in an Include or a `ListenAddress` port, the wizard could block the port `sshd` actually used, sometimes without confirmation. | Ports come from `sshd -T`; the rule is only widened, and narrowed after a verified restart and Keep. |
| D12 | High (regression in this branch, fixed) | Sharing state files for delete made `File.Replace` destroy them on classic NTFS (Server 2008 R2–2016). | A window reading agent state at the wrong moment could delete it. | Classic sharing with retries; a replace that removed the target never deletes the only copy. |

## All findings and their status

Severities are the verified ones. *Fixed* means implemented with regression tests where a test
can run without administrator rights; items marked CI are proven only by the hosted workflows.

**Fixed directly during the review (part 1 and 2 commits):** R1 `Services.Start/Stop` status race
(now `Services.MoveTo`, which also fails at once when a service stops while starting); R2; R3
authorized_keys truncated in place (now replaced by rename, with retries while `sshd` reads it);
R4 PuTTY Ed25519 keys whose private integer is shorter than 32 bytes; R5 Buddhist-era years (2569)
next to Gregorian ones under th-TH; R6; R7 a block applied before its expiry was saved (permanent
block); R8 webhook text could carry links, Slack controls and mentions, and redirects counted as
delivered; R9; R10 editing a partner SFTP rule dropped its `AuthorizedKeysFile` (every partner key
ignored); R11; R12; R13 a failed notify setting lost the new partner's password; R14.

| Area | Fixed | Partly / documented | Not done (owner decision) |
|---|---|---|---|
| Client workspace | C1 reduced standard-user token when the desktop is the same full-token administrator; C2 working folder is the profile; C3 non-UTF-8 files no longer blank the tab; C4 clear message for other-account elevation; C5–C13 | — | — |
| Keys | K2 usable-key counting and lock-out warning in the wizard; K5–K10 (PEM on loose ACLs, passphrase detection, TAB comments, in-process RFC 4716 with the key's comment, secret wiping, leading blank lines) | — | — |
| Partners | P2 unsafe partner root detected and optionally hardened; P6 refused on a domain controller; P7 earlier rules that cover partners reported; P8–P11, P13, P15 | P14 (uncertain): strict group reading on the Partners tab only | — |
| Server window | M1–M4, M6–M13, M15 | — | M14 (ACL grants of an SFTP Apply are not revoked on rollback) |
| Configuration | G1–G5, G7–G11 | G1 step 4 (pre-filling the wizard port) replaced by a note | — |
| Agent | A4, A6, A7, A9, A12, A13 | A11 (zone ids, fallback text); A14 (stale degraded reason) | Counting `Failed publickey` lines toward blocking; clearing a recorded history gap |
| Installer, CI, native | I1, I2 (Disabled / delayed start kept), I4, I7–I13 | I3 documented in INSTALL.md section 7 | I5 x86 install lane; I6 remembering `KEEP_INBOX_OPENSSH` / `ADD_PATH` |

The 25 problems the branch review found in its own first commit (D1–D25: renames failing while
`sshd` reads a key file, temporary files inheriting readable ACLs, links in user profiles, state
files on classic NTFS, the agent stopping when the firewall service is down, and missing tests)
are fixed, except the Slack `unfurl_*` flags (D11: receivers such as Google Chat reject unknown
fields; links are defanged instead).

## Final review of the merged branch

A last review of the merged branch, by area, found these; all are fixed in Manager 2.3.2:

- **Logged-in peers.** A session whose login has left the event log no longer turns automatic
  blocking off: every connected address is spared instead, and only sessions of the installed
  `sshd` count. The Failed logins dialog always opens, so blocks can still be lifted.
- **Restarts.** A changed `Include` no longer refuses the Dashboard and tray Restart for good;
  without a record of the file `sshd` runs, the restart is a plain one (the newest backup could be
  older than that file). A save that fails after its recovery record was written puts the record
  back, and a first save without a previous file never rolls back by deleting it.
- **Keep** never restores the settings just kept when narrowing the firewall fails; the Firewall
  tab shows a failed read instead of throwing. The wizard's administrator key-only choice writes
  rules only.
- **Usable keys** are counted as `sshd` reads and accepts them (no UTF-16 files, Ctrl-Z ends a
  file, unknown options, certificate lines, types outside `PubkeyAcceptedAlgorithms` and RSA below
  `RequiredRSASize` do not count); the account check and the wizard share the count. RFC 4716
  exports keep the comment on one line PuTTY reads.
- **Partners** are not created under a root another account controls; a volume root's DELETE
  permission is not reported as a problem; names ending in `.bak` get a true reason. Key files below
  an administrator's junction (a moved `C:\Users`) are written; only the key file's own folder may
  not be a link.
- **Client.** ssh Connect accepts IPv6 host names; a blocked `cmd.exe` falls back to starting `ssh`
  directly; new non-ASCII text is refused in a non-UTF-8 file; a reduced-token client explains how
  to manage the server.
- **Agent.** An archive held open by a spreadsheet delays only those records; state files are
  replaced through a backup name; a manual unblock is not undone by failures already counted.
- **Installer.** A *Disabled* or delayed start type is kept for a service any package registered,
  not only one in the new `INSTALLFOLDER`.

Two low-severity items it left open were then fixed as well:

- **A cancelled or failed uninstall, or `REMOVE=Server`,** left `sshd` and `ssh-agent` stopped:
  the step that records the running services, and its rollback, ran only when the server or the
  agent was installed. They now also run for a removal, except while an upgrade removes the old
  package (the upgrading package keeps its own record).
- **The setup wizard's port note and firewall summary** assumed the port shown came from the main
  file's `Port` line. When it comes from a `ListenAddress` with a port, or the main file has no
  `Port` line and includes others, the page says that the `Port` line it writes may not decide the
  port, and the summary and preview name the ports `sshd -T` reports for the wizard's own
  `sshd_config`.

## Owner decisions taken as defaults

| Question | Default chosen |
|---|---|
| Client workspace on a full-token administrator desktop of the same account | Run with a SAFER standard-user token |
| Elevation with another administrator's credentials | Not supported for client work; a message names the Start-menu shortcut |
| Partner root writable by other accounts | Offer to restrict it (default No); drive roots and links refused |
| Partners on a domain controller | Refused |
| `sshd_config` containing bytes that are not UTF-8 | Saving refused, naming the lines; restores are byte-exact |
| Service start type over upgrade and repair | Keep an administrator's *Disabled* or *delayed start* for services that ran this package |
| Uninstall removes service registrations that the in-box OpenSSH provided | Documented, with commands to register them again |
| A Keep step that fails after the user clicked Keep | Previous settings restored at once, and said so |
| Exhausted notifications | Kept 30 days, at most 200 per destination |

## Verification

Local, unelevated, on the final branch: **290 unit tests** and **49 GUI checks** pass;
`preinstall.Tests.ps1` **188/188**; two independent pinned builds are identical. Several
regressions were also run against the previous code to confirm that they fail there.

Only the hosted workflows can prove: the MSI changes (sequencing and conditions of the new restore
and rollback actions, upgrade/repair/rollback/uninstall lanes, client-only installs), the
`servconf.c` dump change and its round trips, elevated `--selftest`/`--authtest`/`--keytest`, the
SAFER token path with a real full-token desktop, and the logged-in-peer mapping with real sessions.

## Residual risks

- `FirewallScript` in the MSI is close to its command-line budget (about 380 base64 characters left).
- No hosted lane makes an uninstall fail. The restart after a cancelled uninstall rests on the
  package test of the action conditions and on the script tests of the save and rollback phases.
- A hard link planted through a directory handle held from before a partner-folder reset can
  still receive inherited permissions; the reset then fails and the new account is removed.
- A recovery restore through the SYSTEM task does not keep the replaced file as a backup.
- The XPath that leaves `sftp-server` events out of the failed-login scan is untested on
  Server 2008 R2; a fallback filters in code.
