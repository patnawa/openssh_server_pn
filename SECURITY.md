# Security policy

## Scope

OpenSSH Server PN packages OpenSSH for Windows with its own installer and management console.
Three different parties own the code involved, and vulnerability reports should go to the right one:

| Affected component | Report to |
|---|---|
| OpenSSH itself (protocol handling, `ssh`, `sshd`, `sftp`, key handling) as found in any build, including the official Microsoft packages | The OpenSSH project: [openssh.com/report.html](https://www.openssh.com/report.html) (`openssh@openssh.com`). Windows-port specific code: Microsoft Security Response Center, [msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report), as described in the upstream [PowerShell/Win32-OpenSSH security policy](https://github.com/PowerShell/Win32-OpenSSH/blob/L1-Prod/.github/SECURITY.md). |
| Vendored libraries (LibreSSL, libfido2, libcbor, zlib) | The respective upstream project. We will pick up the fix in the next build; open an issue here so it is tracked. |
| **This project**: the MSI installers and their pre-install script, OpenSSH Server PN Manager, the build scripts and library version choices documented in `docs/`, or the published hashes | This repository, see below. |

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

Releases built by the CI workflow (the builds after 10.5.1.0, see
[docs/RELEASING.md](docs/RELEASING.md)) also carry a CycloneDX SBOM and signed provenance
attestations, which show that a file was built by this repository's workflow from a given
commit: `gh attestation verify <file> --repo patnawa/openssh_server_pn`. They are
Authenticode-signed only when a signing service is configured; the release notes say which.
10.5.1.0 and the manager 1.5.0 release have hashes only.

## Security design of the packages

- **Installer.** The pre-install and firewall steps run as LocalSystem. Their script is embedded
  in the package and cannot be replaced from the command line. The public properties that reach
  it (`FIREWALL_PROFILES`, `KEEP_INBOX_OPENSSH`, `INSTALLFOLDER`) are limited by launch conditions
  to known values, so no property value can change the command. The steps never fail an install,
  and everything they do is written to the MSI log. When the server is removed, the installed
  manager runs as LocalSystem from the install folder to delete its scheduled tasks
  (10.5.4.0 and later). During an interactive first install it also leaves, as LocalSystem, a
  request for the setup wizard in `%ProgramData%\ssh\manager`, which only administrators can read
  or change; the manager the package then starts runs as the installing user and asks for
  administrator rights like any start of the manager, and a request older than 15 minutes is
  ignored.
- **Exposure.** On Windows 10 and 11 the firewall rule applies to Domain and Private networks
  only; on Windows Server to all networks. Password logins are allowed after install so that
  the first login works. INSTALL.md section 5 lists the hardening to apply once keys are set up.
  The Authentication tab of OpenSSH Server PN Manager turns password logins off for everyone or
  for single users and groups.
- **Files and services.** Program files inherit the protected `%ProgramFiles%` permissions,
  `sshd` keeps host keys readable by SYSTEM and Administrators only, and the
  `HKLM\SOFTWARE\OpenSSH` key (which holds `DefaultShell`) is writable by administrators only.
  The Hardening tab of OpenSSH Server PN Manager and `OpenSSHServerPNManager.exe --check` verify all
  of this, and whether SSH is reachable on a public network.
- **OpenSSH Server PN Manager.** It runs elevated and writes configuration only after `sshd -t`
  accepts it. The key generator hands passphrases to `ssh-keygen` through `SSH_ASKPASS`, never on
  a command line. It never displays a private key, and it verifies that each private key is
  readable only by its owner, SYSTEM and Administrators. It converts keys to and from PuTTY's
  `.ppk` format in memory, never through an unprotected temporary file, and reads every exported
  file back before keeping it.
- **Login-method changes.** The Authentication tab warns before a change would leave the
  administrator's own account without a method that works, and checks the result against the
  running server afterwards. It turns off keyboard-interactive, which has no Windows back end.
  Checks that need `sshd` as SYSTEM use a one-off scheduled task. The task runs only `cmd.exe` and
  the installed `sshd.exe`, with its files in a folder only SYSTEM and Administrators can change.
  `--authtest` creates a temporary local account with a random password, usable only through a
  temporary server on 127.0.0.1, and deletes it when the test ends.
- **SFTP-only accounts.** The SFTP tab forces `internal-sftp` and switches terminals and every kind
  of forwarding off for them, so their key or password opens file transfer and nothing else. A
  folder it creates for them gives full control to SYSTEM and Administrators and modify (or read)
  rights to that account or group only; parent folders it has to create are for SYSTEM and
  Administrators only, so no account can create another one's folder next to its own. An existing
  folder keeps its permissions, and the question before *Apply* names an owner or other accounts
  that can open it. `ChrootDirectory`
  is enforced by the Windows port of OpenSSH, which checks every path `sftp-server` opens, not by
  Windows itself, so the account's NTFS permissions are the second line of defence: keep folders
  outside an account's reach closed to it. `--authtest` tries to leave the folder with `..`, a
  drive letter and an upload outside it, and fails if any of them works.
- **SFTP partners.** Partners are local accounts in groups whose rules force `internal-sftp` in a
  folder of their own, as above. Their passwords are generated from a cryptographic random source
  (20 characters), shown once and stored nowhere; they never expire, the partner cannot change
  them, and the accounts are hidden from the Windows sign-in screen. Their public keys are in
  `%ProgramData%\ssh\partner_keys`, which only SYSTEM and Administrators can change, so a partner
  cannot add a key of its own. Disabling or deleting a partner ends its open sessions. Rules that
  keep partners out (`AllowUsers`, `DenyGroups`) and a section changed by hand are reported, not
  overwritten.
- **Alerts and automatic blocking.** Two scheduled tasks run the manager as SYSTEM: the copy
  installed next to `sshd.exe`, or a copy in `%ProgramFiles%\OpenSSH Server PN Manager`, both
  folders only administrators can change. There is no service and no listening port. Settings,
  state, the agent's log and the transfer archive are in `%ProgramData%\ssh\manager`, which only
  SYSTEM and Administrators can open; the SMTP password and the webhook address are encrypted
  there with DPAPI for this computer. Mail is encrypted with STARTTLS when *STARTTLS* is ticked (the
  default); webhook addresses must be `https://`, and TLS 1.2 and 1.3 are enabled also where .NET
  would not offer them by default. Automatic blocking adds addresses to the one inbound block rule
  of the Logs tab; it never blocks this computer, the allow list or an address with a logged-in
  session, so failed attempts from the address of someone logged in (an administrator's included)
  do not cut that address off. Uninstalling the package removes the tasks.