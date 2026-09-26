# Changelog

All builds of this project, newest first. Each entry lists the source, the library versions,
every change to the packaging, and how the result was verified. Published as GitHub releases:
[v10.5.1.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.1.0) (with Manager
1.5.0) and [manager-v1.5.0](https://github.com/patnawa/openssh_server_pn/releases/tag/manager-v1.5.0);
the builds before them were not published.

## Installer and CI after 10.5.1.0 (not released yet)

Changes to the packaging and the release process in the branch `improvements`; they go into the
next build. The OpenSSH source and libraries are unchanged.

Installer:

- **The firewall rule keeps its settings on upgrade.** 10.5.1.0 removed the rule with the old
  package and created it again with port 22 and the default networks, so a server moved to port
  2222 lost remote access after an unattended upgrade. The rule's ports, networks, enabled state
  and allowed remote addresses are now saved before the old package is removed and put back on
  the new rule; a rollback puts them back on the old package's rule. `FIREWALL_PROFILES` and
  `SSHD_PORT` take precedence. To make room for the save step, `InstallExecute` now comes
  before `RemoveExistingProducts` (Windows Installer allows no deferred action between
  `InstallInitialize` and `RemoveExistingProducts`, ICE63).
- **`SSHD_PORT=<n>`** sets the port of the firewall rule and of `sshd_config` (after the services
  started; backup kept; restored when `sshd` does not listen there) and restarts `sshd`.
- **`ACTIVE_SESSIONS=abort`** stops the installation before anything changes (exit code 1603)
  while SSH sessions are open; `close`, the default, ends them as before.
- **Error control Normal** for `sshd` and `ssh-agent` (it was Critical).
- **Native PowerShell for the custom actions** of the x64 and ARM64 packages (`WixQuietExec64`).
  `WixCA` is an x86 binary, and `WixQuietExec` started the 32-bit PowerShell of `SysWOW64`; on
  GitHub's Windows 11 ARM64 runner that emulated PowerShell took about 75 seconds to start, so
  the four steps of an install cost five minutes and a rollback several more.
- **ARM64**: the package scheduled the x86 WiX firewall actions a second time, so the rule was
  created and removed twice; it uses the ARM64 action now.
- The script is embedded as two smaller scripts without comments and with LF line ends, so both
  fit `powershell.exe`'s command line and the package no longer depends on the line endings of
  the checkout; `.gitattributes` pins `preinstall.ps1` to CRLF.
- Verified here without administrator rights: x64, x86 and ARM64 packages built with full ICE
  validation (0 warnings); `tests\preinstall.Tests.ps1` 118 checks passed (the record of the
  live firewall rule read without changing it, `sshd_config` edits including the real
  `sshd_config_default`, ReplaceFile keeping permissions); `tests\package.Tests.ps1` 79 to 80
  checks per package passed (sequence, action types, ErrorControl 32769, launch conditions
  evaluated by Windows Installer: 22, 65535 and 0022 accepted; 0, 65536, `+22`, ` 22` and
  `22' ; calc ; '` refused); the session check started as the package starts it: exit 0 with no
  session, exit 1 with a connection open. **Not run**: an actual install, upgrade, repair,
  rollback or `SSHD_PORT` change; the CI workflow runs these on its first run.

Build:

- **Reproducible executables.** `Directory.Build.targets` next to the Visual Studio projects adds
  `/Brepro` (compiler and linker) and `/PDBALTPATH:%_PDB%` (linker): no time stamps in the
  objects and PE headers, no build-folder path in the debug directory. Two clean x64 builds of
  `ssh-keygen.exe` made minutes apart here were byte-identical (SHA-256 `40BCB7EC…97C9`). The
  vcpkg libraries are not covered yet.

CI and releases:

- `.github/workflows/openssh.yml` builds x64, x86 and ARM64, runs the OpenSSH unit tests
  (ARM64 binaries run for the first time, on windows-11-arm), installs the packages on Windows
  Server 2022 and 2025 and Windows 11 on ARM, runs the manager's `--check`, `--selftest`,
  `--keytest` and `--authtest`, and tests upgrade, repair, a failed installation rolled back (a
  copy of the package with a custom action that fails after `StartServices`), downgrade,
  `SSHD_PORT`, `ACTIVE_SESSIONS` and uninstall. A tag creates a draft release with an SBOM and provenance
  attestations; Authenticode signing when configured.
- `manager.yml`: actions pinned to commit SHAs, a reproducibility report, attestations.
- Weekly upstream version check, Dependabot for actions, winget manifests, Intune notes,
  a pull request template, CODEOWNERS, and issue routing that sends bugs of this build here.
- Verified here: `actionlint` 0 errors in the three workflows; the scripts parse; the unit-test
  runner on the local binaries (7 of 8 binaries pass without administrator rights, 686 tests;
  `unittest-win32compat` needs them); the SBOM of 10.5.1.0 against the CycloneDX 1.5 schema;
  `winget validate`. **None of the workflows has run on GitHub yet.**

## OpenSSH Server Manager 1.6.0 (not released yet)

A safety pass over every save of `sshd_config`, and the window a daily administrator asked for:
a setup wizard, dark mode, a client tab, failed logins by address with a firewall block list,
fixes per hardening check, and an icon in the notification area. Built from the branch
`improvements`; not published yet.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 818,688 bytes | `3DE33B00C2965077870F61833B2139F13B95DDD5BBF663F448B92A37492E1C8D` |

Rebuilt from a fresh CRLF checkout with the same compiler, the executable has the same SHA-256.

Fixed:

- **A restart that locked you out was kept.** *Save and restart* rolled back only when `sshd`
  did not start. A configuration that passes `sshd -t` and starts can still refuse everyone new:
  a typo in `AllowUsers`, a `ListenAddress` this computer does not have, a port the firewall
  blocks. After a restart the server is now checked (every configured port listens and answers
  with an SSH banner, the firewall rule admits the ports, the `AllowUsers`/`DenyUsers`/
  `AllowGroups`/`DenyGroups` of your own account), and you are asked to keep the new settings.
  Without an answer within 60 seconds, or with *Restore*, the previous file comes back and `sshd`
  restarts. When `sshd` does not start, the previous file now comes back without a question (it
  asked before, and *No* left `sshd` stopped).
- **Editing a list removed the lines it did not show.** `sshd` adds up every `AllowUsers`,
  `AllowGroups`, `DenyUsers` and `DenyGroups` line (`servconf.c`: "appends to list"). The field
  showed the first line and a save commented out the others, which changed who may log in. The
  fields now show every line together and a save writes them as one line.
- **Editing Port or ListenAddress removed the other ports and addresses.** The hint said the other
  lines stay; the save commented them out, so `sshd` stopped listening there. Only the first line
  is edited now.
- **`ListenAddress ::1` meant port 1.** The port was read from the text after the last colon, so
  a bare IPv6 address without a `Port` line gave port 1 to the dashboard, the firewall suggestion
  and the checks. Only `[address]:port` and `host:port` carry a port now.
- **A comment after a value blocked saving.** `MaxAuthTries 4 # policy` was read with its comment,
  so the field showed `4 # policy`, and every save of the Settings tab failed its number check.
  Comments after a value are now separated the way `sshd` does it (a `#` at the start of an
  argument, outside quotes) and stay on the line when the value changes. Only changed fields are
  checked.
- **Prose was taken for a commented example.** Setting `Port` could replace a comment such as
  `# Port forwarding is used by ...`; only `#Port 22` (no space after the `#`, as in
  `sshd_config_default`) counts as an example now.
- **Included files.** A new setting is written before the first `Include`, so it wins over an
  included file (`sshd` takes the first value). The Settings tab says when the file includes
  others, and after a save it reports every changed value that `sshd -T` does not show.
- **Changes made meanwhile were overwritten.** A save wrote over `sshd_config` even when another
  program or Notepad had changed it since the window read it. The SHA-256 of the file as read is
  compared first; a changed file is written only after a question, and it is kept as a backup.
- **Backups.** Two saves within one second shared a backup name, so the first backup was lost;
  the second now gets `-2`. The newest 50 backups are kept. The live file is written next to
  `sshd_config` and swapped in with `ReplaceFile`, which keeps its permissions, so a crash or a
  full disk never leaves half a file.
- **The owner of authorized_keys.** `sshd` refuses a key file whose owner is not the account,
  SYSTEM or Administrators. A file written by an administrator whose objects are owned by the
  account (not the Administrators group) was refused; every write now sets such an owner to
  Administrators.
- **The window froze.** Starting and stopping the service (up to 40 seconds each), `sshd -t` and
  `sshd -T`, the SYSTEM check (up to 60 seconds), reading events and the hardening checks ran on
  the window's thread, which then showed "Not Responding". They run in the background now, with
  a progress bar; reading events can be cancelled. Fingerprints of authorized keys are worked out
  once per key instead of by one `ssh-keygen` per key on every reload.
- **The default shell was written at every save.** A save of the Settings tab wrote the default shell
  to the registry every time; it is written only when it changed.
- **The inbox C# 5 compiler could not build the source**, although `build.ps1` fell back to it
  (the source uses exception filters of C# 6). The script now requires the Roslyn compiler, and
  warnings stop the build.

New:

- **Preview before every save**: the lines added and removed, with their context; *Save* or
  *Cancel*. It can be switched off.
- **Access check before every save**: a warning when the account running the manager would be
  refused by `DenyUsers`, `AllowUsers`, `DenyGroups` or `AllowGroups`, decided in the order of
  `allowed_user` in `auth.c`: the lists lower-cased and `DOMAIN/name` read as `domain\name` as
  `servconf.c` does on Windows, and groups matched like `ga_match` in `win32_groupaccess.c` (one
  entry with `*` or `?` makes sshd compare the whole list by name, so `sshusers` then no longer
  matches the domain group `corp\sshusers`).
- **Backups**: a list of the backups with what restoring each one would change; restore or
  delete.
- **Setup wizard**: port and network profiles, your key, key-only login for administrators or
  everyone (offered only once a key is authorized for you), the recommended settings, and
  `AllowGroups`; applied in one save and one restart with the keep-or-restore question.
- **Client tab**: `known_hosts` with fingerprints (remove entries; add a server's keys from
  `ssh-keyscan` after comparing fingerprints), the `Host` blocks of `.ssh\config` (add, edit,
  remove, connect; other lines of a block are kept), and the keys in `ssh-agent` (add with the
  passphrase through `SSH_ASKPASS`, remove, start the agent).
- **Logs tab**: a period (last hour, 24 hours, 7 or 30 days, all), multi-select, *Copy selected*,
  *Export* (CSV, HTML, text), event details with Enter, and *Failed logins by address*: failed and
  abandoned logins by client address with their count, time span and the account names tried
  (the address is read from the end of each message, so a user name such as
  `x from 10.1.2.3 port 22` cannot put an innocent address on the list),
  and a firewall block rule for `sshd`'s ports kept by hand (block, unblock; this computer's own
  addresses are refused, an address with an open SSH connection warns first).
- **Hardening tab**: *Fix selected* (settings in one save and one restart; service, host keys, key
  file permissions and public-network exposure after a question; login methods and login
  restrictions open their tab) and *Export report*.
- **Notification area**: an icon with the service state and a menu; notifications when `sshd`
  stops without the manager stopping it, and when failed logins cross a threshold (10 within 5
  minutes by default).
- **Dark mode and high contrast**: like Windows, light or dark (About tab); dark title bars, lists,
  tabs, status bar and dialogs; high contrast always uses the system colours.
- **Keyboard**: Ctrl+S saves the tab shown, F5 refreshes it, Ctrl+1 to Ctrl+9 open the tabs,
  Ctrl+F, F3 and Shift+F3 find in the text tab, Enter opens and Delete removes the selected item
  of a list. Lists sort by a click on a column header (not the lists whose order matters).
- **Sessions**: several sessions can be selected and disconnected at once.
- **Firewall tab**: asks before the rule is switched off or would no longer allow `sshd`'s port.
- **A new port and the firewall rule**: after a port change the rule gets the new port *added*;
  a rule that had a single port drops the old one only when the new settings are kept, and when
  they are not kept (or `sshd` does not start) the rule gets its old ports back with the old file.
  1.5.0 moved the rule to the new port at once and left it there when the file was rolled back.
- **Connect** (Dashboard and Client tab) starts `ssh` without administrator rights
  (`runas /trustlevel:0x20000`): `ssh` reads the user's own configuration, which can run
  commands, and those must not run with the manager's rights. A host alias that starts with `-`
  is refused, and `--` ends the options.
- **Restart** on the Dashboard asks first, like Stop.
- **Preferences** on the About tab, stored in `HKCU\Software\OpenSSH Server Manager`.
- `--screenshot` also renders the new dialogs and the wizard pages, and takes `--theme dark|light`;
  `build.ps1 -Csc` builds with another Roslyn compiler.

Verification (Windows 11 Pro 26200, not elevated: no administrator rights were available in this
session):

- `--unittest`: all 44 tests passed (20 before), on the fresh build and on the committed executable.
- `--selftest`: 83 of 86 passed. The three failures read the live host keys (`sshd -t` and
  `sshd -T` on the live configuration: "no hostkeys available") and the security of the services,
  which needs administrator rights; they passed elevated with 1.5.0 and the code under them did
  not change. The new window tests pass: a Settings save that keeps the second `Port` line and
  writes the two `AllowUsers` lines as one, a save refused because the file changed meanwhile
  (with a host key of its own, so `sshd -t` runs without administrator rights), the preview's
  added and removed lines, and the dark and light palettes; text still fits at 100% and 150%,
  and every new input has a name for screen readers.
- `--screenshot` in light and dark: every tab, the dialogs and the wizard pages were looked at.
- Not run in this session (they need administrator rights): `--selftest` elevated, `--keytest`,
  `--authtest`, and the manual paths that restart the live service (keep or restore, the failed
  start). Run them elevated before a release.

## OpenSSH Server Manager 1.5.0 (2026-09-26)

A review of the window: three bugs fixed, and the window now keeps unsaved changes, checks fields
as you type, stays responsive while it refreshes, scales on high-DPI displays and names its
controls for screen readers. The program has its own icon. Tested against the installed
10.5.1.0 package, which also found a cleanup bug in `--authtest`.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 652,800 bytes | `B4BCA5D3EE5AF2E3501D6B47B03F9BE228CD5C610CC3C75C5B56144D26D5573E` |

The size grew with the icon, which the executable carries twice: as its Windows icon, and as a
resource the window loads with all ten sizes.

Published in the releases [manager-v1.5.0](https://github.com/patnawa/openssh_server_pn/releases/tag/manager-v1.5.0) and
[v10.5.1.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.1.0), each with `SHA256SUMS.txt`. The first publication, earlier the same day, had an
`.exe.config` that differed between the two releases in its line endings and `SHA256SUMS.txt`
files with CRLF line endings; both releases were published again with one `.exe.config`
(SHA-256 `38607418...98451`, as in `bin`) and LF sums, which `sha256sum -c` reads.

Fixed:

- **A refused save reached the file through another tab.** The Settings tab wrote its fields into
  the configuration all tabs share before checking them. When the save was refused (a field that
  is not a number, an unclosed quotation mark, or `sshd -t`), those edits stayed. The next save of
  another tab then wrote them without showing them: *Apply* on the Authentication tab, *Apply
  recommended settings*, or enabling an ML-DSA key type. For example, *Permit empty passwords*
  **yes** with a mistyped *Max auth tries* was refused, and a later *Apply* of login methods wrote
  `PermitEmptyPasswords yes`. Every save now edits a copy and adopts it only after it was saved.
- **The Authentication tab wrote old rules over the file.** After *Reload*, a save on the text
  tab, *Restore a backup* or *Reset to shipped defaults*, the tab kept its rules. *Apply* then
  wrote them over the rules in the file. All tabs now show the file after such a change. Login-method
  changes not applied yet are kept when the file's login methods did not change.
- **Replacing a key could lose the old one.** The key generator moved an existing key aside before
  it made the new one; when that failed, the old key stayed under its `.bak-` name. It now goes
  back to its place.
- **Headings were smaller than the text.** Thirteen bold headings (the Dashboard captions, section
  titles) used the system default font of 8.25 pt instead of the window's 9.5 pt.
- **`--authtest` left its test profiles behind.** `sshd` keeps a profile loaded, so `--authtest`
  registers a one-time startup task that deletes the profile of its temporary account after the
  next restart. The task ran about ten seconds after boot, when WMI or the User Profile Service
  did not answer yet; it ignored every error, deleted nothing, kept itself and reported success
  (result 0). Two profiles from 25 September survived the restart of 26 September. Run on demand
  once Windows was up, the same task deleted its profile and removed itself. The task now starts
  two minutes after boot, retries for six minutes, and ends with 1 while the profile remains, so
  its result is no longer 0 when nothing happened. The two leftover profiles were cleaned up
  here.
- **Restart and Stop said sessions are disconnected.** They are not: on a service stop, `sshd`
  closes its listening sockets and exits (`sshd.c`), and each connection is a separate
  `sshd-session.exe` process. The texts now say that connected sessions stay connected.

New:

- **Unsaved changes.** The Settings, Authentication and text tabs show `*` when they have changes
  not saved. When another tab saves, typed values stay; the text tab says the file changed and
  that *Save* would write over it. *Reload* on a tab discards that tab's changes only. Closing the
  window lists the tabs with unsaved changes and asks first.
- **Fields checked as you type.** Numbers and the Allow and Deny lists show an error icon and the
  error in red next to the field; *Save* refuses the same errors.
- **Background refresh.** The Dashboard and Sessions refresh every 5 seconds on a background
  thread. Starting one takes under 1 ms of the window's time. Found on the way: the firewall query
  walked every firewall rule through COM, which took about 150 ms per rule on a background thread
  (1,100 rules on the test machine); it now asks for the rule by name, in 6 ms.
- **High-DPI displays.** All sizes scale with the display (the manifest declares system DPI
  awareness, so Windows does not scale the window itself), and buttons are never narrower than
  their text. `--ui-scale 1.5` lays the window out as on a 150% display.
- **Program icon.** A blue Windows 11 style tile with a white key whose head is a small terminal
  showing a `>_` prompt: SSH keys and the shell in one shape. The 16, 20, 24 and 32 px images are
  drawn pixel by pixel, so the title bar and the taskbar show a sharp icon, not a shrunken one.
  The executable carries it for Explorer and the taskbar; the window, its dialogs and the About
  tab use it too. `icon\render.py` draws every size and writes `icon\app.ico`; running it again
  gives the same file. It was chosen from four concepts (key tile, shield, secure tunnel, server
  with lock), each drawn at every size and compared on light and dark backgrounds.
- **Screen readers.** Every text box, list and number field has an accessible name; field errors
  are in its accessible description.

Verification, with the final binary above, against the installed OpenSSH Server PN 10.5.1.0 x64
package (`OpenSSH-Win64-v10.5.1.0.msi`, the hash listed under 10.5.1.0 below):

- **Install:** `msiexec /i ... /qn` from a prompt that was not elevated failed with 1603, Error
  1925 (*You do not have sufficient privileges*), and rolled back, as INSTALL.md says. Elevated,
  it returned 0: `sshd` and `ssh-agent` running with automatic start, port 22 on IPv4 and IPv6,
  the firewall rule for the Domain and Private networks.
- **`--unittest`:** all 20 tests passed, also from a prompt that was not elevated, with
  `__COMPAT_LAYER=RunAsInvoker`.
- **`--selftest`:** all 59 tests passed. The new ones were first seen failing: the three window
  bugs with their reported symptoms (the refused save left `PermitEmptyPasswords yes`, *Reload*
  kept rule `bob` over `carol`, a failed replacement left only `id_old.bak-20260926-120000`); text
  that does not fit (41 places at 150%, then 13 headings in a smaller font, then none); the
  background refresh (it did not finish in 30 s until the firewall query asked for the rule by
  name); the icon test (before `app.ico` existed). The window tests use a scratch `sshd_config`,
  the firewall test a disabled rule of its own, removed afterwards.
- The test with random names ran for the first time and at first claimed too much: `sshd` cannot
  match a `Match User` name that starts with `#`, quoted or not (`match_cfg_line` in
  `servconf.c` reads it as a comment). The Authentication tab already refuses `#` in names. The
  test now checks the Allow and Deny path with all characters (37 names read back by `sshd -T`)
  and the Authentication tab with the names it accepts (22 rules).
- **`--check`:** OK. It warns about keyboard-interactive, which this machine's `sshd_config`
  still leaves on.
- **`--keytest`:** all passed: twelve key pairs (Ed25519, ECDSA P-256, P-384, P-521, RSA 3072 and
  4096, each with and without a passphrase) logged in; a wrong passphrase and an unauthorized key
  were refused. ML-DSA was skipped: not enabled on this server.
- **`--authtest`:** all nine settings passed with real logins.
- **Sessions during Restart and Stop:** a key login to this server printed one line a second for
  40 seconds. It went on through a restart of `sshd`, through 7 seconds with `sshd` stopped, and
  through the start; its two `sshd-session.exe` processes kept their IDs, a new login worked after
  the start, and `ssh` ended with 0 and all 40 lines.
- **The profile-removal task:** re-registered with the fix and run on demand, it deleted the
  profile of an account whose profile was not loaded, then removed itself (0); for the account
  whose profile `sshd` still held, it kept the profile and itself and ended with 1.
- After all runs the live `sshd_config` had its original hash and time stamp;
  `administrators_authorized_keys` was absent, as before; the services, the local accounts and
  the number of firewall rules were unchanged.
- **`--screenshot`:** all tabs, the About tab with the icon, and the rule dialog, at 100% and 150%.
- **CI on GitHub** (`.github/workflows/manager.yml`, its first runs): the first run stopped at the
  build step, because PowerShell does not expand `$env:TOOL` in a bare command name; fixed with
  the call operator. It then passed: all 20 unit tests on the runner's build and on the committed
  executable, and the version check. The runner's compiler (Visual Studio 18) built the same
  bytes as the one here (Visual Studio 2022 Build Tools): SHA-256 `B4BCA5D3...D5573E` on both, so
  the committed executable can be checked against the source.

Not tested here:

- The fixed profile-removal task at a real startup. One task, for the profile `sshd` still
  holds, waits for the next restart of this machine.
- A real 150% or 200% display. `--ui-scale` simulates one; the status bar keeps the system font
  there.
- A screen reader.
- A Kerberos login: no Active Directory domain.

## OpenSSH Server Manager 1.4.0 (2026-09-26)

Account names with an apostrophe work in login rules and in the Allow and Deny fields. The
dashboard says when saved settings are not in effect yet. There is a fast unit-test mode for CI,
and the source is split into one file per area.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 254,464 bytes | `D74BC261405C3AEAD4958DB1F73A04CD037A2D81F026682CD21AA982C9FB6E35` |

The executable is now committed in `tools/OpenSSH-Server-Manager/bin/`. With the Roslyn compiler
the build is deterministic: two builds here gave the same hash.

Fixed:

- **Rules for names with an apostrophe.** Windows allows `'` in account names (`o'brien`). A rule
  for one was written as `Match User o'brien`, and `sshd` rejected the whole file with
  `invalid quotes`, so *Apply* could not save it. `sshd` splits `sshd_config` lines like a shell
  (`argv_split` in `misc.c`): `'` quotes as well as `"`, and `\'`, `\\`, `\"` are escapes. Names
  are now written with the quoting `sshd` expects, and read back the same way. A domain account
  whose name starts with an apostrophe (`contoso\'neil`) was also affected: `sshd` read `\'` as an
  escape and dropped the backslash, so the rule was accepted but never matched. Plain names such
  as `contoso\bob` are written exactly as before.
- **Allow users, Allow groups, Deny users, Deny groups.** These fields were written as typed, with
  the same problem for `o'brien`. They now take names separated by spaces, with "double quotes"
  around a name with spaces, and write each name the way `sshd` reads it.
- **A trailing backslash in a list.** Found by the new random-name test: an argument ending in
  `\` followed by another one was read by `sshd` as an escaped space, which joined the two names.
  A trailing backslash is now doubled.

New:

- **Restart notice.** The dashboard and `--check` say when `sshd_config` was saved after the
  running `sshd` started, so the saved settings take effect only after a restart.
- **`--unittest`.** Runs the 17 tests of the program logic without `sshd`, without the service
  and without administrator rights (set `__COMPAT_LAYER=RunAsInvoker` to skip the elevation
  prompt). `--selftest` runs these plus the tests against the installed server, 45 in all.
- **Property tests of the quoting.** 5,000 random names, from all characters Windows allows plus
  those `sshd` treats specially, must read back unchanged. In `--selftest`, 44 names, fixed ones
  and random ones including Thai letters, are written as rules into a configuration with its own
  host key, and `sshd -T` must apply each rule to its account and to no other.
- **CI.** `.github/workflows/manager.yml` builds the source on every push and pull request that
  touches the manager. It runs `--unittest` on the new build and on the committed executable, and
  fails when the committed executable's version differs from the source. A tag `manager-vX.Y.Z`
  publishes the committed executable with `SHA256SUMS.txt` as a GitHub release.
- **Source layout.** `OpenSSHServerManager.cs` is split into 14 files, one per area (see the
  manager README); no code changed in the move. `build.ps1` compiles every `.cs` file in the folder.

Verification, with the final binary above:

- **`--unittest`:** all 17 tests passed, both elevated and from a non-elevated shell with
  `__COMPAT_LAYER=RunAsInvoker`.
- **The fix, against `sshd -T` of the installed 10.5.1.0 x64 package:** `Match User o'brien`
  failed with `invalid quotes`, and `"o'brien"` applied to `o'brien`. `"contoso\'neil"` did not
  apply to `contoso\'neil`, and `"contoso\\'neil"` did. `contoso\bob` and `"a b"` applied, and a
  rule for `bob` did not apply to `alice`. With the fix, the regression test (rules for `o'brien`,
  `contoso\'neil`, `contoso\bob` and `o'brien smith`, checked with `sshd -T`) and the other 36
  self-tests passed.
- **`--screenshot`:** all tabs rendered; the Settings tab loaded its values.

Not tested here:

- The final `--selftest` run, including the `sshd -T` test with 44 names, could not run: the
  OpenSSH Server PN package was uninstalled from this machine while the work was in progress. The
  server tests that remained failed with `sshd.exe` missing.
- `--keytest`, `--authtest` and `--check`, for the same reason.
- The CI workflow has not run yet; it runs on the first push.
- Saving the Allow and Deny fields from the window. The quoting they use is covered by the unit
  tests, but the fields were not saved against the live server.

## OpenSSH Server Manager 1.3.0 (2026-09-25)

Choose how accounts log in: Windows authentication, public key, Kerberos, or key and password
together, for everyone and per user or group. The tests grew from 28 to 36, and a new end-to-end
login test was added.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 243,200 bytes | `C73796D9CC81CA411B18DB4017CA3BAD44B34DA7ED7B9DED18626A73EFBEF6F2` |

New:

- **Authentication tab.** Tick *Windows authentication* (the account name and the Windows
  password), *Public key* and, on domain members, *Kerberos single sign-on*. With Windows
  authentication and public key both ticked, either one is enough, or both are required, key
  first (`AuthenticationMethods publickey,password`).
- **Rules for users and groups.** An ordered list of `Match User` and `Match Group` blocks in one
  marked section of `sshd_config`, placed before any other `Match` block. The first rule that
  matches an account applies. The rule dialog suggests local accounts and groups, checks that the
  name exists, and stores it the way `sshd` compares it. It refuses well-known groups such as
  *Everyone*, which `sshd` cannot match. A section edited by hand is left alone with an
  explanation. Other `Match` blocks that set login methods are pointed out.
- **Check an account.** *Show its login methods* uses `sshd -T` to work out the methods of any
  account from the settings on the tab, before they are applied. *Ask the running server* shows
  what the server offers an account, through a connection that sends only the user name.
- **Safe apply.** *Apply* asks first. When the new settings would leave your own account without
  a method that works, the question carries a warning and *No* is the default; for example,
  public key only while no key is authorized for you. Then come the usual `sshd -t` check,
  backup, and restart with rollback. At the end, the tab checks that the running server offers
  what was configured.
- **Keyboard-interactive off.** *Apply* on the Authentication tab and *Apply recommended
  settings* write `KbdInteractiveAuthentication no`. OpenSSH for Windows has no
  keyboard-interactive back end. The server offered the method, refused it at once, and counted
  the attempt against `MaxAuthTries`, so a client with several keys could be cut off before its
  password prompt. A new Hardening check reports it (27 checks).
- **`--authtest`**: real logins for nine settings against a temporary `sshd` on 127.0.0.1; see the
  verification below. `--check` now prints the login methods.
- The raw login-method fields left the Settings tab; the Authentication tab replaces them.

Fixed:

- **Name case in `sshd -T` checks.** Checks for your own account passed the login name in its
  original case (`Alpha`). `sshd -T` then skipped a `Match User alpha` block, although the running
  server, which lower-cases the name, applies it. *Allow this key to log in* and the ML-DSA check
  now pass the name as `sshd` sees it.

Found while testing, and handled:

- **Group rules and `sshd -T`.** Run by an administrator, `sshd` cannot create a token for another
  account. It logs "unable to generate user token ... as i am not running as system" and applies
  no `Match Group` block to that account (`get_user_token` in `win32_usertoken_utils.c`). The
  service, which runs as SYSTEM, does apply them. Checks for other accounts therefore run
  `sshd -T` as SYSTEM through a one-off scheduled task whenever the configuration has a
  `Match Group` block. The task runs only `cmd.exe` and the installed `sshd.exe`, from a folder
  that only SYSTEM and Administrators can change.
- **Profiles stay loaded.** `sshd` for Windows loads the account's profile at login
  (`LoadUserProfileW`) and never unloads it. Here the profile was still loaded minutes after the
  last session ended, `reg unload` was refused for Administrators and for SYSTEM, and the profile
  could not be deleted. `--authtest` therefore deletes its temporary account at once and registers
  a one-time startup task. After the next restart, the task deletes the profile, then removes
  itself. The task was run on demand here: it kept the loaded profile and itself, as intended.
  Its boot trigger has not fired yet.
- **Group membership of a new account.** `New-LocalUser` left a new account outside *Users* in a
  test here. `--authtest` adds its account to *Users* explicitly, so that its group rule is
  tested on an ordinary member.

Verification against the installed 10.5.1.0 x64 package, with the final binary above:

- **`--selftest`:** all 36 tests passed. The new tests cover:
  - the login-method round trip through `sshd_config`, and a section edited by hand being left
    alone;
  - the `AuthenticationMethods` logic, and rule order as `sshd -T` applies it;
  - account names in `sshd`'s form, and `sshd -T` as SYSTEM giving the same answer as run by the
    administrator;
  - the lock-out warning, and the running server offering what `sshd -T` works out.
- **`--authtest`:** all nine settings passed with real logins by a temporary account over a
  temporary `sshd` on 127.0.0.1:

  | Setting | Server offers | Password | Key | Key, then password |
  |---|---|---|---|---|
  | Windows authentication only | password | logs in; a wrong password is refused | refused | logs in |
  | Public key only | publickey | refused | logs in | logs in |
  | Either one | password, publickey | logs in | logs in | logs in |
  | Both required | publickey | refused | refused | logs in; a wrong password is refused |
  | Rule for group *users*: public key only (others: Windows authentication) | publickey | refused | logs in | logs in |
  | Rule for the user: Windows authentication only (others: public key) | password | logs in | refused | logs in |
  | User rule (both required) before a group rule (Windows authentication only) | publickey | refused | refused | logs in |
  | Rule for *administrators* only | password | logs in | refused | logs in |
  | Kerberos ticked | gssapi-with-mic, password | logs in | refused | logs in |

  In every case the list the server offered matched what `sshd -T` worked out for the account.
- **`--keytest`:** all key types passed; ML-DSA was reported as not enabled on this server.
- **`--check`:** OK. The new keyboard-interactive check warns on this server, which still runs
  the `sshd` default.
- **`--screenshot`:** all eleven tabs, the example rules and the rule dialog rendered.
- After all runs the live `sshd_config` had its original hash, `administrators_authorized_keys`
  was still absent, and no test account, service or folder remained. The test profiles and their
  one-time removal tasks wait for the next restart, as described above.

Not tested here:

- A Kerberos login: no Active Directory domain was available. The tests show only that the
  server offers `gssapi-with-mic` when the box is ticked.
- Domain accounts and domain groups in rules.
- Clicking *Apply* against this machine's live server. Its steps are covered by the tests above,
  but it would have changed the live configuration.

## 10.5.1.0 (2026-09-25)

The first build of **OpenSSH Server PN** as its own product. OpenSSH 10.5p1 and the libraries are
the same as in 10.5.0.0. Published on 26 September 2026 in the release [v10.5.1.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.1.0),
with OpenSSH Server Manager 1.5.0; `src/` is unchanged since these packages were built.

- **Source in the project.** The server source moved from `openssh-portable/` to `src/` and is
  built from there. Its history, including the upstream history, was kept for future merges; since 26 September 2026 it is kept outside the repository ([BUILDING.md](BUILDING.md#2-layout)).
- **Identity.** The product and manufacturer are *OpenSSH Server PN*, with support links in
  *Apps & features*. The binaries' file properties show the project, and the banner comment is
  `OpenSSH-Server-PN`. The file version is 10.5.1.0. The upgrade codes are unchanged, so earlier
  builds and the official Microsoft packages are still recognised and replaced.
- **Installer.** It now checks what is installed and removes it before installing; see
  [INSTALL.md section 3](INSTALL.md#3-upgrade-reinstall-downgrade). It also has a safer firewall
  default and validates its public properties.

**Packages.**

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSH-Win64-v10.5.1.0.msi` | 6,901,760 bytes | `5BC5FD7CCFC27940AA2F9377F066DBE4F48421F3422E432AEB6CEEACEF2326B8` |
| `OpenSSH-Win32-v10.5.1.0.msi` | 6,119,424 bytes | `4F8E1BB626238E11BC7DDBE7B18A3086924A00592CBA4AD571AAD67F8D00671F` |
| `OpenSSH-ARM64-v10.5.1.0.msi` | 6,791,168 bytes | `A7107F66AA73B284D3454B2AB4477E19A1008CB75D29A4720B68B1F4EB98DF70` |

All three build from `src/` with zero warnings and zero errors in the packaging step. The
OpenSSH compile shows the same 17 known warnings as 10.5.0.0 and no errors.

**What changed in the installer.**

| Change | Reason |
|---|---|
| `MajorUpgrade` replaced by explicit `Upgrade` rows for all three upgrade codes. Older and same versions of any architecture are removed before the install | A rebuilt package of the same version failed with 1638, and an x86 package could sit next to an x64 one with both registering `sshd` |
| A newer installed version of any architecture stops the install with a clear message; `ALLOWDOWNGRADE=1` overrides it | Accidental downgrades stay blocked, also across architectures; a deliberate rollback no longer needs a manual uninstall |
| New deferred action `OpenSSHPreInstall` right after `RemoveExistingProducts`. It stops the services and ends the OpenSSH processes that would keep files locked | Locked files made upgrades end with "restart required" and a mix of old and new binaries |
| The action keeps the process tree that runs the installation, so an upgrade over SSH keeps its own session | An administrator must not cut the session that is running the upgrade |
| Processes are ended only when they run from this package's folder, the in-box folder or the registered `sshd` folder | Other OpenSSH builds, such as Cygwin, MSYS2 or Git, must not be touched |
| The in-box *OpenSSH Server* capability is removed with DISM; `KEEP_INBOX_OPENSSH=1` keeps it. A DISM failure is logged and the install continues | The capability registers the same `sshd` service, and servicing it points the service back at the in-box binary |
| The `sshd.exe` process mitigation under *Image File Execution Options* is re-applied after that removal. If Windows finishes the removal only at the next restart, a one-time startup task re-applies it after the restart and deletes itself | The capability owns that key and deletes it on removal. The package's own component had skipped writing it because the key existed when the install began |
| The action runs for install, upgrade, repair and removal, and is skipped for a maintenance run that only adds a feature. `REMOVE=Client` or `REMOVE=Server` touch only that feature | Adding a feature replaces no file and must not end sessions |
| **Firewall profiles by edition.** A second action sets the rule's networks after WiX creates it: all networks on Windows Server, Domain and Private on Windows 10 and 11. `FIREWALL_PROFILES` overrides this | The rule applied to every network since 10.2.0.0, so a workstation on public Wi-Fi exposed SSH, with password logins allowed by default |
| **Property validation.** Launch conditions accept only known values for `FIREWALL_PROFILES` and `KEEP_INBOX_OPENSSH`, and refuse an apostrophe in `INSTALLFOLDER` | These values reach a single-quoted PowerShell command that runs as LocalSystem. On a machine with the unsafe `AlwaysInstallElevated` policy, a crafted value could otherwise have run code as SYSTEM |
| The actions never fail an install: the script always exits 0 and both actions use `Return="ignore"` | The cleanup improves an upgrade; it must never become a reason for an upgrade to fail |
| The script is PowerShell 2.0 compatible, embedded as base64 by a build step in `openssh.wixproj`, and run in PowerShell of the package's bitness. Every line it prints goes to the MSI log with the prefix `preinstall:` | No native custom action DLL to build or sign, and readable diagnostics |
| `ALLOWDOWNGRADE`, `KEEP_INBOX_OPENSSH` and `FIREWALL_PROFILES` are secure custom properties; the script text lives in a private property | Command-line properties reach the elevated part of the install; the script cannot be replaced from the command line |
| ARM64 package declares Windows Installer 5.0 | WiX raised the value itself with warning CNDL1143 |
| Package builds use `/t:Rebuild` | WiX's MSBuild targets track only file inputs, so a rebuild with a new `ProductVersion` silently produced the previous package |

Windows Installer allows nothing between `InstallInitialize` and `RemoveExistingProducts`; it
fails with error 2613. The cleanup therefore runs right after the previous package is removed.
That is enough: files the previous package could not delete because a process still held them
are moved aside and deleted at the end of the transaction, which succeeds once the cleanup has
ended those processes. Every uninstall, including the nested one in a later upgrade, runs the
same cleanup before it stops services and removes files.

**Build tooling fixes** in `src/`, needed to build from a subfolder and useful for any fresh
checkout:

- The build helpers found the source root by the nearest `.git` folder, which is the repository
  root when the source lives in `src/`. They now look for `version.h` and `contrib\win32\openssh`.
- `Install-VcpkgDependencies.ps1` let vcpkg install into its flat default layout and then checked
  the nested layout that MSBuild uses, so it failed on every fresh tree. It now passes
  `--x-install-root` and produces the nested layout.

**Security review of an installed server** (Windows 11 Pro, this package). Only administrators,
SYSTEM and TrustedInstaller can change the program folder and its files. The same holds for
`%ProgramData%\ssh`, `sshd_config`, the logs, `HKLM\SOFTWARE\OpenSSH` (which holds `DefaultShell`)
and the two services. Only SYSTEM and Administrators can read the private host keys. Both
service paths are quoted, and the `sshd.exe` process mitigation is in place. The effective
configuration offers no weak ciphers, MACs, key exchanges or host key algorithms. One exposure
was found: the firewall rule applied to the machine's Public Wi-Fi network while password logins
were allowed. The new firewall default above closes it for Windows 10 and 11. The review also
found the property-injection path above. OpenSSH Server Manager 1.2.0 now repeats these checks
on demand.

**Verification** on Windows 11 Pro 26200, one scenario after the other on the same machine, with
an SSH session open where the table says so. The test harness checked services, files,
processes, pending file renames, the firewall rule and the startup task after every step.

With the release packages above:

| Scenario | Result |
|---|---|
| Upgrade over the previous 10.5.1.0 build (same version, new product code), session open | Exit 0. The session's processes were ended and no file rename was left for a restart. Product name, publisher and banner show *OpenSSH Server PN*, and the firewall rule was set to Domain and Private. Key login, `Restart-Service` and a forced kill of `sshd.exe` all passed |
| Four crafted property values (`FIREWALL_PROFILES` with an apostrophe or `public`, `KEEP_INBOX_OPENSSH=2`, an `INSTALLFOLDER` with an apostrophe) | Each stopped by its launch condition with its message, exit 1603. No action ran and nothing changed |
| Fresh install with `FIREWALL_PROFILES=all`, then with `FIREWALL_PROFILES=private` | Rule set to all networks, then to Private |
| `msiexec /fa` repair with and without `FIREWALL_PROFILES` | The rule is not recreated in a repair and keeps its profiles |
| x86 package over x64, then x64 over x86 | Both exit 0; services moved to `Program Files (x86)` and back. The x86 package set the rule from 32-bit PowerShell |
| Uninstall with a session open, then install | Exit 0 both. The session ended, the startup task was removed on uninstall, and nothing was left for a restart. The full check passed after the install |

With earlier builds of this release that had the same pre-install logic but not yet the identity
and firewall changes:

| Scenario | Result |
|---|---|
| Older package (10.5.0.9 test build) | Exit 1603 with the downgrade message, nothing changed. With `ALLOWDOWNGRADE=1` exit 0; then the newer package again, exit 0 |
| Older x86 package over the newer x64 install | Exit 1603, nothing changed |
| Install started inside an SSH session (`ssh localhost msiexec ...`) | Exit 0; the two processes of that session were kept and the session stayed up |
| `ADDLOCAL=Client` with a session open | Cleanup skipped, session kept |
| `REMOVE=Client` with a session open, then `ADDLOCAL=Client` | Server untouched and session kept; client files removed and restored |
| `ssh-agent` pointed at the in-box 9.5 binary, then `msiexec /fa` | OpenSSH Server Manager reported it; the repair restored the registration |
| In-box *OpenSSH Server* capability installed | Exit 0. DISM removed the capability, finishing at the next restart, and `sshd` ran from `Program Files` |
| In-box capability already pending removal | Exit 0, removal skipped, mitigation checked and startup task registered |
| Startup task and helper functions, tested in isolation as SYSTEM | 17 checks passed: the value is written only when missing, a custom value is kept, and the task deletes itself |
| Silent install from a non-elevated prompt | Error 1730 and rollback, installed package untouched. This is standard Windows Installer behaviour and is documented |

Limits of this verification:
- **In-box removal.** Removing an *installed* in-box capability ran with an earlier revision of
  the script, which made the same DISM call without the state query before it. Windows allows
  the capability back only after the restart that completes the first removal, so the final
  script could not repeat it.
- **Startup task.** Its boot trigger needs a restart to fire; the task body was run on demand
  instead.
- **Windows Server.** The all-networks firewall default was not tried on a Windows Server install.
  The rule is set by the same code path that the `FIREWALL_PROFILES=all` test exercised.
- **ARM64.** Static checks only.

## OpenSSH Server Manager 1.2.0 (2026-09-25)

A key-pair generator, a security audit, and the result of a review of every function (24
defects fixed). The tests grew from 17 to 28, and a new end-to-end key test was added.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 168,448 bytes | `2DEBE76313F2CB76CD9EEE4EDEB1FB7238B49B77A4FDAD4428A219F0467EF257` |

New:

- **Key generator tab.** Creates Ed25519 (recommended), ECDSA P-256/384/521, RSA 3072/4096 and
  experimental ML-DSA-44+Ed25519 key pairs with `ssh-keygen`. Every key is verified before it is
  shown:
  - the private key must reproduce the saved public key;
  - an encrypted key must not open without its passphrase;
  - only the user, SYSTEM and Administrators may read the private key, which is the rule the ssh
    client enforces.

  A key that fails a check is deleted, and an existing key is never overwritten but kept under a
  dated name. The passphrase goes to `ssh-keygen` through `SSH_ASKPASS`, with the console itself
  as the helper and the secret in its environment. It never appears on a command line, which
  process-creation auditing and Sysmon record. *Allow this key to log in* adds the public key to
  the file `sshd` reads for the account, as reported by `sshd -T -C`. *Test login with this key*
  logs in to this server with that key only, with the host key pinned to the server's own keys.
- **ML-DSA.** OpenSSH 10.5 compiles the algorithm in but leaves it out of the default accepted
  algorithms on both server and client. The generator labels it experimental and offers to add
  it to `PubkeyAcceptedAlgorithms`, with a validated save and a restart that rolls back on
  failure.
- **`--keytest`** runs the whole flow unattended against the local server and restores
  `authorized_keys` byte for byte afterwards.
- **Security checks** on the Hardening tab and in `--check`:
  - who can change the program folder and its programs, `sshd_config`, the logs, the
    `DefaultShell` registry key and the two services;
  - who can read the private host keys;
  - whether SSH is reachable on a network that is currently Public;
  - login grace time and minimum RSA key size.
- **Service binary check.** Warns when Windows servicing has pointed `sshd` or `ssh-agent` at the
  in-box binary, and `--check` counts that as a problem.
- **Apply recommended settings** now also sets `LoginGraceTime 60` and `RequiredRSASize 2048`.
- **File properties.** Version information in the file properties.

Fixed:

- **Keys.** Adding or removing a key rewrote `authorized_keys` from its parsed key lines, which
  deleted every comment. The whole file is now kept. *Add my public key* and *Add* compared the
  wrong field for duplicates and could skip a new key; they compare the key material now.
  *Add my public key* also asks `sshd` which file applies instead of assuming the administrators
  file. The owner of a user's `authorized_keys` is resolved from the profile list; a renamed
  account previously got a file it could not read.
- **Key types.** ML-DSA (`ssh-mldsa44-ed25519@openssh.com`), `webauthn-` and certificate key
  lines were rejected. Host key types with a hyphen (`MLDSA44-ED25519`, `ED25519-SK`) showed as
  "?", which also made the host key check warn on every 10.5 install. The key type columns were
  too narrow for these names.
- **Configuration input.** A value with a line break could add a second directive to
  `sshd_config`; values and subsystem commands must now be single lines. Saving settings wrote
  every field, normalising lines and commenting out repeated directives such as several
  `ListenAddress` lines; it writes only changed fields now.
- **Saving.** Saving no longer re-adds a deliberately removed `Subsystem sftp`, and it validates
  a default shell only when you change it. The text editor adopted a configuration that
  `sshd -t` had rejected, and a 32,767-character limit blocked typing.
- **Firewall.** A rule with several ports was collapsed to one port on *Apply* and after a port
  change. The list is now kept, and you are asked before it changes.
- **Sessions.** IPv6 peers, including `ssh localhost` over `::1`, are shown. Durations over 24
  hours no longer wrap.
- **.NET Framework 4.5 and 4.5.1** (Windows 8.1, Server 2012 R2) failed on the dashboard. The
  start mode is now read from the registry, and the service PID comes from the service control
  API instead of localized `sc` output.
- **Stability.** The refresh timer no longer re-enters while a dialog is open. Unattended modes
  never show a dialog. `sshd.log` is read from the end only. The Logs tab splitter is sized after
  layout.
- **Hardening.** *Agent forwarding* was always OK and is now informational. A failed `sshd -T`
  is reported instead of judging empty values. ACLs that cannot be read without elevation are
  reported as such, not as "too open".

Verification against the installed 10.5.1.0 x64 package:

- **`--selftest`:** all 28 tests passed. They include generating every key type with a
  passphrase through `SSH_ASKPASS`, and detecting a folder that grants Everyone write access.
- **`--keytest` with the default server configuration:** all passed. That covers six key types,
  each with and without a passphrase: generated, verified, authorized, logged in and removed. A
  wrong passphrase and an unauthorized key were refused. ML-DSA was reported as not enabled.
- **`--keytest` with ML-DSA temporarily enabled:** the two ML-DSA variants passed as well.
  `sshd_config` was then restored and matched its original hash.
- **`--check`:** no warnings after the hardening in INSTALL.md section 5. Before it, the check
  had flagged the public-network exposure and the grace-time, RSA-size and login-restriction
  settings.
- **`--screenshot`:** all ten tabs rendered without an error.

## 10.5.0.0 (2026-09-25)

**Source.** `openssh-portable/` (`src/` since 10.5.1.0), branch `merge-v10.5P1-20260925` of the
repository history before 26 September 2026, now kept in the history bundle
([BUILDING.md](BUILDING.md#2-layout)): the
maintainers' V_10_3_P1 merge ([PowerShell/openssh-portable PR #877](https://github.com/PowerShell/openssh-portable/pull/877),
head `a3d1079`, CI green) followed by our merges of upstream OpenSSH `V_10_4_P1` (2026-07-06)
and `V_10_5_P1` (2026-08-11), done tag by tag with the maintainers' merge rules
(`.github/instructions/merge/`). Reported version: `OpenSSH_for_Windows_10.5p1`, file version
`10.5.0.0`. This is three upstream releases ahead of the Windows port's `latestw_all` (10.2p1).

**Packages.**

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSH-Win64-v10.5.0.0.msi` | 6,873,088 bytes | `094F147982FE5E3B39047B7BBEF93F272F6034EEEEC03EAD6BC5B322F042D85B` |
| `OpenSSH-Win32-v10.5.0.0.msi` | 6,094,848 bytes | `CD713C5D9CEE9A481CF4AB110D7D450F0B2E5DFFA457FD80891E80ECEDAA4EF8` |
| `OpenSSH-ARM64-v10.5.0.0.msi` | 6,606,848 bytes | `EFCC59433334773F14F0BD1E6285B5AC383A4A8E4B300975CCD9E5BCA099AE48` |

**What the upstream merges bring** (server side, from the OpenSSH release notes): GSSAPI
pre-authentication denial-of-service fix, complete `PubkeyAcceptedAlgorithms` enforcement for
ECDSA keys, `internal-sftp` argument truncation fix, `principals=""` matching fix, `restrict`
now also blocks tunnel forwarding, `ChannelTimeout` and `RekeyLimit` honoured inside `Match`,
multiple `RevokedKeys` files, the `invaliduser` class in `PerSourcePenalties`,
`GSSAPIDelegateCredentials`, stricter transport checks during rekeying, the hybrid
`mlkem768nistp256-sha256` key exchange, and the experimental `ssh-mldsa44-ed25519@openssh.com`
composite post-quantum signature key type (enabled in this build). Client side: `ssh -O channels`
multiplexing command, `ssh-keygen` FIDO flag editing, and many fixes.

**Conflict resolutions and Windows follow-ups** (all in `openssh-portable/`, commits after
`a3d1079`, in the history bundle):

| Change | Reason |
|---|---|
| Generated files (`*.0` man pages, `ChangeLog`, `configure`, `config.h.in`, `moduli.0`) taken from upstream; `.gitignore` kept the Windows block; workflow files taken from upstream then normalised to `workflow_dispatch` only | Maintainers' conventions |
| `version.h`: Windows fields kept, bumped to `OpenSSH_for_Windows_10.4` then `10.5`; `version.rc` synced with `Sync-VersionResource.ps1` | Pattern 7 |
| `servconf.h`: upstream's 10.4 table-driven `ServerOptions` layout taken; `servconf.c`: dropped the removed `RefuseConnection` default, kept the `#ifdef WINDOWS` path handling; `readconf.c`: upstream's `ret = -1` error semantics with the fork's null initialisers | Prefer upstream |
| `regress/addrmatch.sh`, `cfgmatch.sh`, `knownhosts-command.sh`, `sshsig.sh`, `cfgparse.sh`: upstream's case-insensitive matching (mixed-case `sshd -G` output since 10.4) with the fork's CRLF handling re-applied | Pattern 5 |
| `libssh.vcxproj`: added `libcrux-mlkem-mldsa.c`, `ssh-mldsa-eddsa.c` (10.4) and `kexmlkem768ecdh.c` (10.5) | New upstream sources |
| `kexmlkem768ecdh.c`: `<endian.h>` guarded with `HAVE_ENDIAN_H` | Same guard the fork applies in `kexmlkem768x25519.c` |
| `config.h.vs`: `USE_MLDSA` defined | `defines.h` only enables it after a configure check for variable-length arrays; without it the ML-DSA key type was compiled out and `unittest-sshkey` failed |
| `win32compat/ssh-agent/connection.c`, `keyagent-request.c`: `config.h` included after the Windows headers and before `agent-request.h` | 10.5's `sshkey.h` defines `EVP_PKEY`/`EC_KEY` as `void` when `WITH_OPENSSL` is not yet defined, which collided with LibreSSL 4.3.2's typedefs (`C2628`) |
| Libraries: LibreSSL 4.3.2, libfido2 1.17.0, libcbor 0.14.0, zlib 1.3.2, vcpkg baseline `10541e31`; installer `client.wxs` ICE18 fix and `server.wxs` firewall rule for all profiles | Carried over from the 10.2.0.0 build |

New compiler warnings: 20 x `C4715` (not all control paths return a value) in the generated
`libcrux-mlkem-mldsa.c`, because `KRML_HOST_EXIT` maps to `fatal_f()` which MSVC does not know
to be non-returning. Left unchanged (upstream-generated code); harmless at run time.

**Verification (x64, Windows 11 Pro 26200).**

| Step | Result |
|---|---|
| Unit tests (`unittest-bitmap`, `hostkeys`, `kex`, `match`, `misc`, `sshbuf`, `sshkey`, `win32compat`) | 8 binaries, 767 tests, all passed |
| Install over the 10.2.0.0 MSI (`msiexec /qn`) | exit 0, `sshd.exe` 10.5.0.0, `libcrypto.dll` 4.3.2.0, `%ProgramData%\ssh` preserved (a fourth host key, `ssh_host_mldsa44_ed25519_key`, was generated on first start) |
| Banner and key login | `SSH-2.0-OpenSSH_for_Windows_10.5`; `whoami` over SSH returned the user |
| `Restart-Service sshd`, forced kill of `sshd.exe` | service back within seconds, login succeeds both times |
| Services and firewall | `sshd` and `ssh-agent` Running / Automatic, recovery RESTART x3, firewall rule enabled for all profiles |
| `ssh -Q key` | includes `ssh-mldsa44-ed25519@openssh.com` |
| x86 and ARM64 | built and packaged from the same tree with the same vcpkg triplets; x86 `ssh.exe -V` under WOW64 reports `OpenSSH_for_Windows_10.5p1, LibreSSL 4.3.2`; ARM64 static checks only |

The maintainers' bash regression suite and their `Test-OpenSSHFunctionality.ps1` were not run
here: the latter uninstalls the production `sshd` service on the build machine. The
maintainers' CI covers those when the merges land upstream.

## OpenSSH Server Manager 1.1.0 (2026-09-25)

First release of the management GUI in `tools/OpenSSH-Server-Manager` (see its README for the
function list and safety design). 1.1.0 adds the Sessions tab (live `sshd-session.exe`
processes with owning user, start time and duration, established connections with peer address,
disconnect one or all) on top of the 1.0.0 feature set.

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSHServerManager.exe` | 114,688 bytes | `ED08EC4E56DEA82902B44F592C723F887AD511837EC1D329289506175E41E6BD` |

Built with the Roslyn C# compiler from Visual Studio 2022 Build Tools 17.14 against the .NET
Framework 4.8 runtime assemblies (`build.ps1`); runs on any .NET Framework 4.x, AnyCPU.

Verification on Windows 11 Pro 26200 against the installed 10.2.0.0 server:

| Step | Result |
|---|---|
| `--selftest` (17 tests: config parser round-trip, Set/Get/comment-out semantics, `sshd -t` accepts valid and rejects invalid candidates, authorized_keys write with SYSTEM/Administrators-only ACL, key parser, host keys, service, listeners, banner, firewall API, event log API, default shell registry, `sshd -T`, hardening checks) | all passed |
| `--check` | RESULT: OK (sshd Running/Automatic, listening on 0.0.0.0:22 and [::]:22, `sshd -t` OK, firewall rule enabled for all profiles, 3 host keys) |
| `--screenshot` (all 9 tabs rendered off-screen) | no exceptions; screenshots in `docs/images` |
| Sessions tab with a live key-authenticated session open | shows the SYSTEM monitor process and the user session with start time, plus the established connection with its peer address; the temporary test key was removed afterwards |
| Interactive start | window opens, dashboard refreshes every 5 s, closes cleanly |

Also added: `docs/COMPARISON-BITVISE.md`, a feature audit of this server against Bitvise SSH
Server and other leading SSH servers with ranked improvement candidates.

## 10.2.0.0 (2026-09-25)

**Source.** `PowerShell/openssh-portable`, branch `latestw_all`, commit
[9a43b12c3d1dcb9b742d6b65e5f23d8022017a62](https://github.com/PowerShell/openssh-portable/commit/9a43b12c3d1dcb9b742d6b65e5f23d8022017a62)
("Merge pull request #876 from tgauth/merge-v10.2P1", 2026-09-15). Reported version:
`OpenSSH_for_Windows_10.2p1`, file version `10.2.0.0`.

**Packages.**

| File | Size | SHA-256 |
|---|---|---|
| `OpenSSH-Win64-v10.2.0.0.msi` | 6,561,792 bytes | `BCCF245A9D193C175B08D84C9CAE15C999377C453F716CF90E508FB2B8A8C85B` |
| `OpenSSH-Win32-v10.2.0.0.msi` | 5,820,416 bytes | `A6DD584ABEE34051E39E1A9B88FB3E305CD32A6E0759944866C780EE83F074A8` |
| `OpenSSH-ARM64-v10.2.0.0.msi` | 6,291,456 bytes | `9B6D9D2A5BA412C63C335301CD4A68AFACA9292E7A2FDD66DDB265204EF62CBB` |

**Library changes** (in `contrib/win32/openssh/vcpkg.json` and `vcpkg_overlay_ports`), compared
with the official 10.0.0.0 release:

| Library | Official 10.0.0.0 | This build | Why |
|---|---|---|---|
| LibreSSL | 4.2.0 | 4.3.2 (2026-05-26) | Current stable; includes 4.2.1 TLS 1.3 HelloRetryRequest fix and Windows portability fixes |
| libfido2 | 1.16.0 | 1.17.0 (2026-04-15) | Security advisory YSA-2026-01: restricted `webauthn.dll` search paths; CTAP 2.3 |
| libcbor | 0.14.0 | 0.14.0 | unchanged |
| zlib | 1.3.2 | 1.3.2 | unchanged |
| vcpkg baseline | `a345bbdc` (2024-12-04) | `10541e31` (2026-09-25) | Current helper ports |

Overlay-port maintenance: `vcpkg_overlay_ports/libressl/aarch64-windows.diff` was removed because
LibreSSL 4.3.2 ships the identical `crypto/arch/aarch64/crypto_cpu_caps_windows.c` and selects it
for Windows in its own CMake files. All other LibreSSL and libfido2 patches applied unchanged.
`add-version-file.patch` now stamps `libcrypto.dll` as 4.3.2.0.

**Packaging changes** (in `contrib/win32/install`):

- `server.wxs`: firewall exception `Profile="private"` changed to `Profile="all"`, so
  domain-joined Windows Servers accept connections without a manual rule. This matches the inbox
  Windows OpenSSH feature. Restrict with
  `Set-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' -Profile Private` if needed.
- `client.wxs`: `<CreateFolder />` added to the `ClientPATH` component to satisfy WiX 3.14
  validation (ICE18). No behavioural change.
- ARM64 MSI: WiX raises `InstallerVersion` from 200 to 500 automatically (required for ARM
  packages).

**Toolchain.** Visual Studio 2022 Build Tools 17.14 (MSVC 14.44.35207, Windows SDK 10.0.26100),
Spectre-mitigated libraries, vcpkg 2026-07-27, WiX 3.14.1.8722. Release builds, `/Qspectre`,
`/guard:cf`, `/CETCOMPAT` (x86 and x64), static C runtime, 0 compiler errors, 7 warnings per
architecture (`C4047` in `ssh`/`sshd-session`/`sshd-auth`, `CS1668` from the config project).

**Verification.**

| Step | Result |
|---|---|
| Install x64 MSI over the official 10.0.0.0 MSI (Windows 11 Pro 26200), `msiexec /qn` | exit 0, `sshd.exe` 10.2.0.0, `%ProgramData%\ssh` preserved |
| Services after install | `sshd` and `ssh-agent` Running, start type Automatic, failure actions RESTART x3 (reset 86400 s) |
| Listener and banner | `0.0.0.0:22`, `[::]:22`; `SSH-2.0-OpenSSH_for_Windows_10.2 Win32-OpenSSH-GitHub` |
| Public-key login as an administrator (`administrators_authorized_keys`) | `whoami` returned the user; temporary key removed afterwards |
| `Restart-Service sshd` | service Running, login succeeds |
| Forced kill of `sshd.exe` (process terminated) | Service Control Manager restarted it within 6 s (new PID), login succeeds |
| Firewall | rule enabled, profile Any (this repository) |
| Uninstall / reinstall cycle | exit 0 both ways, configuration preserved |
| x86 binaries under WOW64 | `ssh.exe -V` reports `OpenSSH_for_Windows_10.2p1 ..., LibreSSL 4.3.2` |
| ARM64 binaries | built and packaged; static checks only (no ARM64 hardware) |
| Machine reboot | not performed in this cycle; services are Automatic with recovery, which is the mechanism that survives a reboot |

**Known issues.** None found. The packages are unsigned; SmartScreen may warn on first launch of
the MSI.
