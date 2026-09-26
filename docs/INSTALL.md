# Installing OpenSSH for Windows

This guide covers the MSI packages built by this repository. The official Microsoft packages install
the same way; differences are called out where they exist.

## 1. Choose a package

| Package | Use on |
|---|---|
| `OpenSSH-Win64-v<ver>.msi` | 64-bit Windows client and every Windows Server edition, including Server Core |
| `OpenSSH-Win32-v<ver>.msi` | 32-bit Windows client only |
| `OpenSSH-ARM64-v<ver>.msi` | Windows 10 / 11 on ARM |

Requirements: Windows 7 SP1 / Windows Server 2008 R2 or later, and local administrator rights
for the installation. No Visual C++ redistributable or .NET runtime is needed; the binaries
statically link the C runtime. See [COMPATIBILITY.md](COMPATIBILITY.md) for the full matrix.

Verify the download first. The hash must match the value in the README or in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\OpenSSH-Win64-v10.5.1.0.msi -Algorithm SHA256
```

## 2. Install

Interactive (double-click) and silent installs both work. The MSI has no user interface pages;
run it from an elevated prompt for a log:

```powershell
msiexec /i .\OpenSSH-Win64-v10.5.1.0.msi /qn /norestart /l*v "$env:TEMP\openssh-install.log"
```

| Property | Default | Effect |
|---|---|---|
| `ADDLOCAL=Client` | both | Client tools only (`ssh`, `scp`, `sftp`, `ssh-keygen`, `ssh-agent`, `ssh-add`, `ssh-keyscan`, helpers) |
| `ADDLOCAL=Server` | both | Server only (`sshd`, `sshd-session`, `sshd-auth`, `sftp-server`, `ssh-shellhost`, plus the shared tools) |
| `ADD_PATH=0` | `1` | Do not add `%ProgramFiles%\OpenSSH` to the system `PATH` |
| `INSTALLFOLDER=<path>` | `%ProgramFiles%\OpenSSH` | Alternate install folder |
| `ALLOWDOWNGRADE=1` | unset | Replace an installed newer package with this one (section 3) |
| `KEEP_INBOX_OPENSSH=1` | unset | Leave the in-box Windows *OpenSSH Server* capability installed; its `sshd` registration is still taken over (section 6) |
| `FIREWALL_PROFILES=` | by edition | Networks the firewall rule applies to: `all`, `domain,private`, `domain` or `private`. Unset: all networks on Windows Server, Domain and Private on Windows 10 and 11 |

The installer accepts only these values for `FIREWALL_PROFILES` and `KEEP_INBOX_OPENSSH`, and no
apostrophe in `INSTALLFOLDER`. Any other value stops the install with a message before anything
changes, because these values reach a step that runs as LocalSystem.

Examples:

```powershell
msiexec /i .\OpenSSH-Win64-v10.5.1.0.msi ADDLOCAL=Client /qn          # workstation, client only
msiexec /i .\OpenSSH-Win64-v10.5.1.0.msi ADDLOCAL=Server ADD_PATH=0 /qn  # server, no PATH change
msiexec /i .\OpenSSH-Win64-v10.5.1.0.msi REMOVE=Server /qn            # drop the server feature later
```

What the installer configures:

- Files in `%ProgramFiles%\OpenSSH`, including `LICENSE.txt`, `NOTICE.txt`, `moduli`,
  `sshd_config_default`, `openssh-events.man` (ETW manifest) and the helper scripts
  `FixHostFilePermissions.ps1`, `FixUserFilePermissions.ps1`, `OpenSSHUtils.psm1`.
- Services `sshd` ("OpenSSH SSH Server") and `ssh-agent` ("OpenSSH Authentication Agent"),
  start type **Automatic**, recovery policy: restart on first, second and subsequent failures,
  counter reset after one day. Both services are started at the end of the install.
- Inbound firewall rule **OpenSSH SSH Server Preview (sshd)**, TCP 22, program-scoped to
  `sshd.exe`. On Windows Server it applies to all networks, so domain-joined and workgroup
  servers are reachable. On Windows 10 and 11 it applies to Domain and Private networks only, so
  a laptop on public Wi-Fi does not expose SSH. `FIREWALL_PROFILES` overrides both, and the
  Firewall tab of OpenSSH Server Manager changes it later. An upgrade recreates the rule with
  these defaults, so pass `FIREWALL_PROFILES` again if you use a different setting. Official
  Microsoft packages enable the rule for Private only.
- The product appears as **OpenSSH Server PN** in *Apps & features*, with links to this project.
- Registry keys `HKLM\SOFTWARE\OpenSSH` (with `agent` subkey) and the process-mitigation
  entries for `sshd.exe` and `ssh-agent.exe` under `Image File Execution Options`.
- Nothing in `%ProgramData%\ssh`. `sshd` creates `sshd_config` from `sshd_config_default` and
  generates host keys on its first start, so an existing configuration is preserved.

## 3. Upgrade, reinstall, downgrade

Run the new MSI over whatever is there. Since build 10.5.1.0 the installer checks what is
installed and clears it before it copies a single file:

1. **Installed packages** are removed first: an older build or the same version of any
   architecture. A rebuilt package replaces the installed one; the old refusal with exit code
   1638 is gone. x86, x64 and ARM64 register the same services, so only one of them can be
   present. Official Microsoft packages use the same upgrade codes and are replaced the same way.
   The feature selection, client only or server only, is carried over.
2. **Services** `sshd` and `ssh-agent` are stopped, whichever package or method registered them.
3. **Leftover OpenSSH processes** are ended. These are open sessions, `sftp-server` and
   `ssh-shellhost` running from this package's folder, the in-box folder or the folder of the
   registered `sshd` service, plus client tools started from this package's folder. Other OpenSSH
   builds such as Cygwin, MSYS2 or Git are not touched. Nothing keeps a file locked, so the
   upgrade finishes without a restart and with a consistent set of binaries. Before 10.5.1.0 an
   upgrade with an open session ended with "restart required" and the old binaries in use.
4. **The in-box Windows *OpenSSH Server* capability** is removed if present (section 6).
5. Files, services, firewall rule and registry entries are re-created and the services started.

All of this runs inside one Windows Installer transaction: if the install fails, the previous
package is restored. The cleanup in steps 2 to 4 is best effort and never fails an install. If
it cannot run at all, Windows Installer falls back to its usual handling of files in use and
may ask for a restart. `%ProgramData%\ssh`, with its configuration, host keys and logs, is never
touched. Back it up anyway:

```powershell
robocopy "$env:ProgramData\ssh" "$env:ProgramData\ssh-backup-$(Get-Date -Format yyyyMMdd)" /E /COPYALL
```

Every step is written to the `msiexec` log (`/l*v`); the lines start with `preinstall:`.

**Downgrade.** Installing a package older than the installed one stops with exit code 1603 and
the message *A newer version of OpenSSH from this package series is already installed*. Nothing
is changed. This also applies across architectures, for example an older Win32 package over a
newer Win64 install. To roll back deliberately:

```powershell
msiexec /i .\OpenSSH-Win64-v10.5.0.0.msi ALLOWDOWNGRADE=1 /qn /norestart
```

**Adding or removing a feature later** (`ADDLOCAL=`, `REMOVE=`) goes through the same package.
Adding a feature replaces no file, so the cleanup is skipped and open sessions stay connected.
Removing a feature touches only that feature: `REMOVE=Client` leaves the server and its
sessions alone, and `REMOVE=Server` leaves client tools that are in use alone.

**Repair.** `msiexec /fa <package.msi>` rewrites every file and re-registers both services,
using the same cleanup as an upgrade. Use it when a service no longer points at the installed
binaries; OpenSSH Server Manager reports that as *Service binary* on its Hardening tab.

**Upgrading from inside an SSH session.** The session that runs `msiexec` (and everything it
started) is kept alive; all other sessions are ended. The old copies of the two files that
session still holds are deleted at the next restart, the new files are already in place and new
logins use them immediately. `msiexec` returns 0.

**ZIP-based installations** (`install-sshd.ps1`): the `sshd` and `ssh-agent` registrations are
taken over by the package and point to `%ProgramFiles%\OpenSSH` afterwards. The files in the old
folder are not removed; delete them by hand. Running `uninstall-sshd.ps1` first is no longer
needed.

**Silent installs must run elevated.** `msiexec /qn` started from a non-elevated prompt cannot
ask for elevation and fails with error 1730 as soon as an installed package has to be removed.
This is standard Windows Installer behaviour (the official packages behave the same);
double-clicking the MSI or running `msiexec` from an elevated prompt works.

## 4. Verify

```powershell
ssh -V                                                     # OpenSSH_for_Windows_10.5p1 ..., LibreSSL 4.3.2
Get-Service sshd, ssh-agent | Select-Object Name, Status, StartType
sc.exe qfailure sshd                                       # RESTART actions present
Get-NetTCPConnection -LocalPort 22 -State Listen           # 0.0.0.0:22 and [::]:22
Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' | Select-Object Enabled, Profile, Action
ssh localhost                                              # password login as the current user
```

If `ssh localhost` prompts for a password and then opens a shell, the server works. The events
of `sshd` are in Event Viewer under *Applications and Services Logs / OpenSSH / Operational*.

## 5. Configure

### Public-key authentication

The quickest way is the **Key generator** tab of OpenSSH Server Manager. It creates an
Ed25519, ECDSA, RSA or ML-DSA key pair in `%UserProfile%\.ssh`, protected by a passphrase, with
the permissions ssh requires. It can add the public key to the file `sshd` reads for your account
and log in with it to prove it works. Give other servers the `.pub` file, never the private key.
ML-DSA-44+Ed25519 is experimental in OpenSSH 10.5: the server and the client must both list it
in `PubkeyAcceptedAlgorithms`. The generator offers to enable it on this server.

By hand:

- Standard users: `%UserProfile%\.ssh\authorized_keys` on the server, one public key per line.
- Members of the local **Administrators** group: `%ProgramData%\ssh\administrators_authorized_keys`,
  which must be readable by `SYSTEM` and `Administrators` only:

  ```powershell
  Add-Content "$env:ProgramData\ssh\administrators_authorized_keys" (Get-Content .\id_ed25519.pub)
  icacls "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
  ```

  This behaviour comes from the `Match Group administrators` block at the end of
  `sshd_config`; remove that block to use per-user files for administrators too.

### Login methods

Accounts can log in with their Windows password (*Windows authentication*), with a public key,
or with Kerberos on domain members. The **Authentication** tab of OpenSSH Server Manager chooses
the methods for everyone, can require key and password together, and adds rules for single users
or groups, for example public key only for administrators. It warns before a change would lock
you out and checks the result with the running server.

By hand, the directives are `PasswordAuthentication`, `PubkeyAuthentication`,
`GSSAPIAuthentication` and `AuthenticationMethods`, globally or in `Match User` and
`Match Group` blocks. Test what an account gets with
`sshd -T -C user=<name>,host=localhost,addr=127.0.0.1` (elevated). Give the name in lower case,
because `sshd` compares it that way. For another account run this as SYSTEM, because an
administrator's `sshd -T` cannot see another account's groups and skips `Match Group` for it.

### Default shell

`cmd.exe` is the default. Switch to PowerShell:

```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String -Force `
  -Value 'C:\Program Files\PowerShell\7\pwsh.exe'
```

### sshd_config

Edit `%ProgramData%\ssh\sshd_config` and restart the service (`Restart-Service sshd`). Test the
configuration before restarting: `sshd.exe -t` from `%ProgramFiles%\OpenSSH` (run elevated).
OpenSSH Server Manager does both for you and rolls back if the restart fails.

Hardening, in the order to apply it. Put the lines above the `Match Group administrators` block:

```
# low risk: apply now (OpenSSH Server Manager, Hardening tab, "Apply recommended settings")
LogLevel VERBOSE            # logs the key fingerprint of every login
LoginGraceTime 60
ClientAliveInterval 300
RequiredRSASize 2048
MaxAuthTries 4              # clients with more than four keys in their agent need IdentitiesOnly
KbdInteractiveAuthentication no   # no Windows back end: it only uses up one of the MaxAuthTries

# who may log in: only the listed groups (an account outside them is refused even with a key)
AllowGroups administrators "openssh users"

# once a key login works for every account that needs one
# (Authentication tab: untick Windows authentication, or add a rule for a group)
PasswordAuthentication no
```

The Hardening tab checks all of this, plus the permissions on the program folder, the
configuration, host keys, registry and services, and whether SSH is reachable on a public
network.

### PowerShell remoting over SSH

Add the subsystem line to `sshd_config`, then `Restart-Service sshd`:

```
Subsystem powershell C:/progra~1/PowerShell/7/pwsh.exe -sshs -NoLogo
```

Clients connect with `Enter-PSSession -HostName server -UserName user`.

## 6. Windows Server notes

- **Server Core**: install with the silent `msiexec` command; there is no UI dependency. All
  verification steps above work from the Server Core console or a remote PowerShell session.
- **Firewall profiles**: domain-joined servers use the Domain profile, and a workgroup server's
  network is often categorised Public. On Windows Server the rule therefore applies to all
  networks. Narrow it at install time with `FIREWALL_PROFILES=domain,private`, or later:

  ```powershell
  Set-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' -Profile Domain,Private
  ```

  With the official package, which allows Private only, add a rule for the Domain profile:

  ```powershell
  New-NetFirewallRule -Name 'sshd-domain' -DisplayName 'OpenSSH SSH Server (sshd)' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Domain,Private
  ```

- **Inbox OpenSSH feature**: Windows Server 2019 and later can also install OpenSSH as an
  optional capability (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`). It lives
  in `%SystemRoot%\System32\OpenSSH` and registers the same `sshd` service name. There is only
  one `sshd` service, and this package takes the registration over. While the capability stays
  installed, Windows servicing of it can point the service back at the in-box binary. The
  installer therefore detects the capability and removes it with DISM before copying files;
  the DISM output is in the MSI log. `KEEP_INBOX_OPENSSH=1` skips the removal. The removal is
  best effort: if DISM fails, the install continues with this package's `sshd` in charge, and
  the log names the command to remove the leftovers later.
  The capability owns the `sshd.exe` process mitigation under *Image File Execution Options*
  and deletes it on removal; the installer puts it back. When Windows can only finish the
  removal at the next restart, the installer registers a one-time startup task, *OpenSSH Restore
  sshd Mitigation*. The task re-applies the mitigation after that restart and deletes itself.
  The in-box *client* capability is left alone. The package's folder is placed first on `PATH`,
  so `ssh` resolves to the new binaries, and the in-box `ssh-agent` registration is taken over.
- **Service account**: `sshd` runs as `LocalSystem` and needs the privileges the installer grants
  (`SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`,
  `SeImpersonatePrivilege`). Group Policy that strips privileges from `LocalSystem` will break
  logins.
- **Reboot**: no reboot is required by the installer. After a reboot both services start
  automatically; the recovery policy restarts `sshd` if it ever crashes.

## 7. Uninstall

```powershell
msiexec /x .\OpenSSH-Win64-v10.5.1.0.msi /qn
```

or through *Apps & features* / `Programs and Features`. The uninstaller ends open sessions and
other OpenSSH processes first (the session it was started from is kept), then removes the
services, the firewall rule and the program files without leaving anything for the next restart.
It leaves `%ProgramData%\ssh` (configuration, host keys, logs) in place; delete it manually if
you want a clean slate.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| `sshd` service will not start | Event Viewer, *OpenSSH / Operational*. Usual causes: syntax error in `sshd_config` (`sshd.exe -t`), host keys with wrong permissions (`FixHostFilePermissions.ps1`), port 22 in use (`Get-NetTCPConnection -LocalPort 22`). |
| Key login refused, password works | Permissions on `authorized_keys` or `administrators_authorized_keys` (`FixUserFilePermissions.ps1` / `icacls` as above); the key type must be enabled server-side. |
| Connection refused from the network, works on `localhost` | Firewall profile. `Get-NetConnectionProfile` shows the active profile; compare with `Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)'`. |
| Garbled interactive session on Windows 10 before 1809 or Server 2016 | Expected; the fallback terminal has limits documented in the [TTY/PTY wiki page](https://github.com/PowerShell/Win32-OpenSSH/wiki/TTY-PTY-support-in-Windows-OpenSSH). |
| `scp` or `sftp` fail from a client after install | The system `PATH` change takes effect in new sessions only; sign out and back in, or restart the service that launches your shell. |
| Install stops with exit 1603 and *A newer version of OpenSSH from this package series is already installed* | You are installing an older package. Add `ALLOWDOWNGRADE=1` or install a newer one. |
| A `preinstall: warning:` line in the MSI log | The install succeeded; one cleanup step could not be done, and the line says which and what to run. The usual case is DISM being busy with another servicing operation, which leaves the in-box OpenSSH Server files in place. |
| OpenSSH Server Manager shows *Service binary* WARN, or `sc qc sshd` names `System32\OpenSSH` | Windows servicing pointed the service back at the in-box binary. Run `msiexec /fa <package.msi>` to repair, and remove the in-box capability so it does not happen again. |
| Error 1730 *You must be an Administrator to remove this application* | Silent install from a non-elevated prompt. Run `msiexec` elevated. |
| Restart pending after an upgrade | Expected when the upgrade ran from inside an SSH session, because the old copies of the files that session held are deleted at the restart. Also expected when Windows could only finish removing the in-box server at the restart. Everything else is already in place. |

More: the upstream [Troubleshooting Steps](https://github.com/PowerShell/Win32-OpenSSH/wiki/Troubleshooting-Steps)
wiki page applies to these packages as well.
