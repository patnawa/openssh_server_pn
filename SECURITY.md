# Security policy

## Scope

OpenSSH Server PN packages OpenSSH for Windows with its own installer and management console.
Three different parties own the code involved, and vulnerability reports should go to the right one:

| Affected component | Report to |
|---|---|
| OpenSSH itself (protocol handling, `ssh`, `sshd`, `sftp`, key handling) as found in any build, including the official Microsoft packages | The OpenSSH project: [openssh.com/report.html](https://www.openssh.com/report.html) (`openssh@openssh.com`). Windows-port specific code: Microsoft Security Response Center, [msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report), as described in the upstream [PowerShell/Win32-OpenSSH security policy](https://github.com/PowerShell/Win32-OpenSSH/blob/L1-Prod/.github/SECURITY.md). |
| Vendored libraries (LibreSSL, libfido2, libcbor, zlib) | The respective upstream project. We will pick up the fix in the next build; open an issue here so it is tracked. |
| **This project**: the MSI installers and their pre-install script, OpenSSH Server Manager, the build scripts and library version choices documented in `docs/`, or the published hashes | This repository, see below. |

## Reporting an issue in this repository's packages

Use GitHub private vulnerability reporting on this repository
(*Security* tab, *Report a vulnerability*) so the report stays confidential until a fixed build is
available. Include the package file name, its SHA-256, the Windows version and architecture, and
the steps to reproduce. Do not open a public issue for anything that could be exploited before a
fix exists.

You can expect an acknowledgement within seven days. Fixed packages are announced in
[docs/CHANGELOG.md](docs/CHANGELOG.md) and on the Releases page. There is no bug bounty.

## Supported builds

Only the most recent build listed in the README receives fixes. Older packages should be
replaced with the newest one, or with an official Microsoft release.

## Integrity of the packages

The MSI files are not Authenticode-signed. The SHA-256 hashes of every build are in
`docs/CHANGELOG.md`, those of the current build also in the README, and every published release
carries a `SHA256SUMS.txt`. Verify a download
with `Get-FileHash <file> -Algorithm SHA256` before installing, and treat any mismatch as a
tampered file.

## Security design of the packages

- **Installer.** The pre-install and firewall steps run as LocalSystem. Their script is embedded
  in the package and cannot be replaced from the command line. The public properties that reach
  it (`FIREWALL_PROFILES`, `KEEP_INBOX_OPENSSH`, `INSTALLFOLDER`) are limited by launch conditions
  to known values, so no property value can change the command. The steps never fail an install,
  and everything they do is written to the MSI log.
- **Exposure.** On Windows 10 and 11 the firewall rule applies to Domain and Private networks
  only; on Windows Server to all networks. Password logins are allowed after install so that
  the first login works. INSTALL.md section 5 lists the hardening to apply once keys are set up.
  The Authentication tab of OpenSSH Server Manager turns password logins off for everyone or
  for single users and groups.
- **Files and services.** Program files inherit the protected `%ProgramFiles%` permissions,
  `sshd` keeps host keys readable by SYSTEM and Administrators only, and the
  `HKLM\SOFTWARE\OpenSSH` key (which holds `DefaultShell`) is writable by administrators only.
  The Hardening tab of OpenSSH Server Manager and `OpenSSHServerManager.exe --check` verify all
  of this, and whether SSH is reachable on a public network.
- **OpenSSH Server Manager.** It runs elevated and writes configuration only after `sshd -t`
  accepts it. The key generator hands passphrases to `ssh-keygen` through `SSH_ASKPASS`, never on
  a command line. It never displays a private key, and it verifies that each private key is
  readable only by its owner, SYSTEM and Administrators.
- **Login-method changes.** The Authentication tab warns before a change would leave the
  administrator's own account without a method that works, and checks the result against the
  running server afterwards. It turns off keyboard-interactive, which has no Windows back end.
  Checks that need `sshd` as SYSTEM use a one-off scheduled task. The task runs only `cmd.exe` and
  the installed `sshd.exe`, with its files in a folder only SYSTEM and Administrators can change.
  `--authtest` creates a temporary local account with a random password, usable only through a
  temporary server on 127.0.0.1, and deletes it when the test ends.