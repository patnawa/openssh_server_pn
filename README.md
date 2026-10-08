# OpenSSH Server PN

## Downloads: 10.5.7.0 / Manager 2.3.1

Published **8 October 2026** as unsigned regular releases. **Manager 2.3.1 is Latest.**

**Manager 2.3.1:** [Download the EXE](https://github.com/patnawa/openssh_server_pn/releases/download/release-manager-v2.3.1/OpenSSHServerPNManager.exe)
and its **[required `.exe.config` file](https://github.com/patnawa/openssh_server_pn/releases/download/release-manager-v2.3.1/OpenSSHServerPNManager.exe.config)**.
Save both files in the same folder. [Manager release notes](https://github.com/patnawa/openssh_server_pn/releases/tag/release-manager-v2.3.1)
and [SHA256SUMS.txt](https://github.com/patnawa/openssh_server_pn/releases/download/release-manager-v2.3.1/SHA256SUMS.txt).

**Server and client packages 10.5.7.0:** [x64 MSI](https://github.com/patnawa/openssh_server_pn/releases/download/release-v10.5.7.0/OpenSSH-Win64-v10.5.7.0.msi),
[x86 MSI](https://github.com/patnawa/openssh_server_pn/releases/download/release-v10.5.7.0/OpenSSH-Win32-v10.5.7.0.msi),
[ARM64 MSI](https://github.com/patnawa/openssh_server_pn/releases/download/release-v10.5.7.0/OpenSSH-ARM64-v10.5.7.0.msi).
[Product release notes](https://github.com/patnawa/openssh_server_pn/releases/tag/release-v10.5.7.0)
and [SHA256SUMS.txt](https://github.com/patnawa/openssh_server_pn/releases/download/release-v10.5.7.0/SHA256SUMS.txt).

These are **unsigned regular releases**, assembled from the exact GitHub-hosted branch
build artifacts for source [098e124](https://github.com/patnawa/openssh_server_pn/commit/098e124).
They have no Authenticode publisher signature or cryptographic build attestation.
The Actions run records, compiler metadata and checksums document their origin; compare
download hashes with the release's `SHA256SUMS.txt`. See the
[release policy](docs/RELEASING.md#unsigned-regular-releases).

[Hosted manager validation](https://github.com/patnawa/openssh_server_pn/actions/runs/37773127926)
passed **164 unit tests, 49 GUI checks and 13 installer-fixture checks**, with the same
executable hash as the reviewed local build. The [full product run](https://github.com/patnawa/openssh_server_pn/actions/runs/37773128497)
passed all required gates: x64/x86/ARM64 builds, native unit/crypto/configuration tests,
and all four installation lanes (Server 2022, Server 2025, PowerShell 2.0 and Windows 11
ARM64). Each lane passed **212 installed self-tests**, actual SYSTEM process-termination
recovery and wizard launch, alongside client-only, authentication, SSH/SFTP and installer
lifecycle checks. Signing, actual reboot and GUI-click recovery, other-account UAC and
manual accessibility/multiple-monitor acceptance remain pending. See the [verification record](docs/IMPROVEMENT-PLAN.md)
and [VM validation guide](docs/VALIDATION.md).

| Release file | SHA-256 |
|---|---|
| `OpenSSHServerPNManager.exe` (2.3.1) | `EF1B84B5A1D5D3FE63579CEB50E614795DE77C95B1090042BE044B81B3090EA3` |
| `OpenSSH-Win64-v10.5.7.0.msi` | `03659f8895cd400b0838209ae59ff0db36f2842fafe13daf80fedd3e377678a1` |
| `OpenSSH-Win32-v10.5.7.0.msi` | `ba7eb6b3d45d8b1e4f119f7a15b30f834aeec33d1db26df2bdeb2f1a6fab8dc7` |
| `OpenSSH-ARM64-v10.5.7.0.msi` | `ce5022c4047d70452b0c87cea167ac99585e1f53e23714b3b7f30fbc848d8beb` |

The manager extracted from each of the three MSIs matches the tested executable hash above.

**OpenSSH Server PN** is an OpenSSH server and client for Windows with its own installer and a
management console. It builds on OpenSSH 10.5p1 and the Windows port of OpenSSH, and adds an
installer that cleans up whatever was installed before, a GUI with a setup wizard, a key-pair
generator and security checks, SFTP accounts for partners outside the company with a transfer
history, alerts by e-mail or webhook with automatic blocking of attacking addresses, and a
firewall rule that stays off public networks on Windows 10 and 11. Windows password logins stay on after installation, as in the official package, until
you have set up keys; the manager's setup wizard switches them off for administrators.

| Folder | Contents |
|---|---|
| `src/` | The server and client source: OpenSSH 10.5p1 with the Windows port, the vendored-library manifest (LibreSSL 4.3.2, libfido2 1.17.0) and the WiX installer. The repository history starts on 26 September 2026; the earlier history, with upstream OpenSSH's, is kept outside the repository for merging new OpenSSH releases ([BUILDING.md](docs/BUILDING.md#2-layout)) |
| `tools/OpenSSH-Server-PN-Manager/` | [OpenSSH Server PN Manager](tools/OpenSSH-Server-PN-Manager/README.md), the management console (C# source, build script, the built executable) |
| `docs/` | Installation, compatibility, building, releasing, changelog, feature audit and roadmap |
| `.github/`, `tools/release/` | CI (build, unit and install tests of the packages, the management console), release tooling (SBOM, upstream version check) |
| `packaging/` | winget manifests and Intune / Configuration Manager deployment notes |

This project is independent: it is not affiliated with Microsoft or the OpenBSD OpenSSH project.

## Historical testing preview: 10.5.6.0 / Manager 2.3.0 (2026-10-08)

Download the **unsigned, testing-only prereleases**:
[product 10.5.6.0](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-v10.5.6.0-r3)
or [Manager 2.3.0](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-manager-v2.3.0-r3).
Keep `OpenSSHServerPNManager.exe.config` beside the manager executable and compare
downloads with `SHA256SUMS.txt`. At their publication, **10.5.5.0 / Manager 2.2.1**
remained the regular release. These r3 releases remain prereleases; their tags, assets
and hashes below are retained unchanged.

The October audit follow-up adds a normal-user client workspace, conflict-checked
configuration and trust editing, durable restart recovery, incremental transfer
history, delivery retries and health reporting, and stricter build/package release
gates. The preview artifacts were built and tested locally: **162 manager unit tests
and 49 automated GUI checks passed**, along with native compilation and focused
parser, installer-script and extracted-package checks. They do not carry
GitHub-hosted build provenance or artifact attestations.

At preview publication, elevated installation, authentication/SFTP and
process-termination/reboot recovery acceptance were pending, as were signing,
ARM64 runtime execution and manual accessibility/multiple-monitor checks. This is the
historical preview record; the regular release's evidence is recorded above.
See the [audit](docs/AUDIT-2026-10-08.md),
[verification plan](docs/IMPROVEMENT-PLAN.md) and [VM validation guide](docs/VALIDATION.md).

| Preview file | SHA-256 |
|---|---|
| `OpenSSH-Win64-v10.5.6.0.msi` | `431C7536E1C15DCA5CBAABA72B1788194B5FD714B46790DB3E0427A31D6E6BC5` |
| `OpenSSH-Win32-v10.5.6.0.msi` | `581849CA68B5AE52A736FE4E2CEC1913C17D657ECDCEB4843A40A4B11912EA19` |
| `OpenSSH-ARM64-v10.5.6.0.msi` | `F2AC4A7A3E826A4E0C6957E95E3717C200277540C0334B5363F2DDA8331A3521` |
| `OpenSSHServerPNManager.exe` (2.3.0) | `86AE48A2D5EBF97D51391A1505E04247C4FCA3A78665E82F7E5DEA75EADA25FD` |

## Previous regular release: 10.5.5.0 / Manager 2.2.1 (2026-09-29)

This maintenance release fixes configuration precedence, transfer reporting, background-job
state races, installer rollback ports, and GUI save, selection, refresh, and theme defects.
The manager passes 100 unit tests. See the [changelog](docs/CHANGELOG.md), [project audit](docs/AUDIT-2026-09-29.md),
and [GUI audit](docs/GUI-AUDIT-2026-09-29.md).

Download [product 10.5.5.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.5.0)
or [Manager 2.2.1](https://github.com/patnawa/openssh_server_pn/releases/tag/manager-v2.2.1).
Keep the manager's `.exe.config` beside the executable. The release includes `SHA256SUMS.txt`,
a CycloneDX SBOM, and GitHub provenance attestations. Files are unsigned.

| File | SHA-256 |
|---|---|
| `OpenSSH-Win64-v10.5.5.0.msi` | `65C0CEF5C666D344C51E670F4AF8F431254444BC31EAD5089F90C5A6CC3A8A12` |
| `OpenSSH-Win32-v10.5.5.0.msi` | `43405B185408AAF330A16DA90BBF71CB8503AE66ACA7C1D8C74B126223A64A9D` |
| `OpenSSH-ARM64-v10.5.5.0.msi` | `C3B3479C476E6D8754F04C19C4A4203D3C5048742443D0655861BDFBDEC71ECE` |
| `OpenSSHServerPNManager.exe` (2.2.1) | `88D2C3F7BCCEBF925406FC365498B8ABE193485DF08024B0A15A763302EB1FA2` |

## Previous build: 10.5.4.0 (2026-09-27)

| Package | Target | Size | SHA-256 |
|---|---|---|---|
| `OpenSSH-Win64-v10.5.4.0.msi` | Windows x64: every Windows Server edition, 64-bit Windows 10 and 11 | 7.1 MB | `187B2EAF3D8DB2CEF056EDCB37087E122B8D1C7F9313B55FF67CBF3EBBFD7C18` |
| `OpenSSH-Win32-v10.5.4.0.msi` | Windows x86: 32-bit Windows client editions | 6.3 MB | `58CFD7882B08BC424C666070C9C31A6BF38DFBFB254EB69F578705ADC0BBDBFD` |
| `OpenSSH-ARM64-v10.5.4.0.msi` | Windows 10 and 11 on ARM | 6.8 MB | `B85157439DFAA966DAE3560C390BC976347E8588DEC6BC02EAD5FC0680571BE6` |
| `OpenSSHServerPNManager.exe` (2.2.0) | Management console, any Windows with .NET Framework 4.5 or later, all architectures; also inside the packages | 1.1 MB | `80F4A90F6EF903DBE523D1452C4CD08A18D8B57F7AFE4975302B7FBAF305BEC8` |

10.5.4.0 replaces 10.5.3.0. The packages now install **OpenSSH Server PN Manager 2.2.0** next to the
server, with Start-menu shortcuts, open its setup wizard after a first installation run with a window,
and remove its scheduled tasks when the server is uninstalled. Manager 2.2.0 adds:

- **SFTP partners**: accounts for customers, suppliers and auditors, each confined to a folder of its
  own, with a generated password shown once, download-only access, key-only login or a last day,
  created and removed without touching `sshd_config` again after a one-time setup;
- **a transfer history**: every upload, download, rename and refused request by period and account,
  as CSV or an HTML report, kept for a year;
- **alerts** by e-mail or webhook (Microsoft Teams, Slack and others) when `sshd` stops, failed logins
  pile up, a partner's files arrive or the disk runs low, a monthly transfer report, and **automatic
  blocking** of addresses with many failed logins, run by two scheduled tasks as SYSTEM.

OpenSSH, LibreSSL and the other libraries are those of 10.5.3.0, so SFTP with AES keeps the speed that
10.5.3.0 brought on x64 (about 3.5 times that of 10.5.2.0); [docs/SFTP-PERFORMANCE.md](docs/SFTP-PERFORMANCE.md)
has the measurements, the settings for each client and a test for your own server. The installer runs
its steps on the Windows PowerShell 2.0 of Windows 7 and Windows Server 2008 R2, where 10.5.1.0 and earlier hung
([docs/INSTALL.md](docs/INSTALL.md#a-hung-installation) says how to end such an installation).
Details in [docs/CHANGELOG.md](docs/CHANGELOG.md) and [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md#run-time-tests).

Download them from the release [v10.5.4.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.4.0), together with
`OpenSSHServerPNManager.exe.config` (keep it next to the executable), `SHA256SUMS.txt` and the SBOM
`OpenSSH-Server-PN-v10.5.4.0.cdx.json`. The matching management console release is
[manager-v2.2.0](https://github.com/patnawa/openssh_server_pn/releases/tag/manager-v2.2.0), the same file. The files are **unsigned**: always compare
the SHA-256 hash before installing (`Get-FileHash .\OpenSSH-Win64-v10.5.4.0.msi`, or the check in
[docs/INSTALL.md](docs/INSTALL.md#1-choose-a-package)). `gh attestation verify <file> --repo patnawa/openssh_server_pn`
shows that a file was built by this repository's workflow. Anyone can rebuild them with
[docs/BUILDING.md](docs/BUILDING.md). Installed, the product appears as *OpenSSH Server PN* in
*Apps & features*, and the server identifies itself as `SSH-2.0-OpenSSH_for_Windows_10.5 OpenSSH-Server-PN`.

Component versions recorded for 10.5.5.0:

| Component | Version | Note |
|---|---|---|
| OpenSSH | 10.5p1, file version 10.5.5.0 | Three releases ahead of the Windows port's `latestw_all` branch (10.2p1). How the 10.3, 10.4 and 10.5 releases were merged is in the changelog |
| LibreSSL | 4.3.2 (2026-05-26) | The official 10.0.0.0 Windows package shipped 4.2.0, without AES-NI. x64: with the CPU detection for Visual Studio builds, so AES-NI and PCLMULQDQ are used. ARM64: with LibreSSL's workaround for the compiler defect ([libressl/portable#1403](https://github.com/libressl/portable/issues/1403)) |
| libfido2 | 1.17.0 (2026-04-15) | Includes YSA-2026-01 (restricted `webauthn.dll` search path) |
| libcbor, zlib | 0.14.0, 1.3.2 | |
| Installer | WiX 3.14 | Removes whatever is installed first, installs OpenSSH Server PN Manager 2.2.1; see below |

Highlights of OpenSSH 10.3 to 10.5 on the server side: a GSSAPI pre-authentication
denial-of-service fix, complete `PubkeyAcceptedAlgorithms` enforcement for ECDSA keys, the
`internal-sftp` argument truncation fix, `restrict` also blocking tunnels, `ChannelTimeout` and
`RekeyLimit` inside `Match`, several `RevokedKeys` files, the `invaliduser` penalty class, the
`mlkem768nistp256-sha256` hybrid key exchange, and the experimental
`ssh-mldsa44-ed25519@openssh.com` post-quantum key type.

## Installer

Run the MSI over whatever is there. Before it copies a file it:

- removes an installed package of this series, of any version and architecture, including the
  official Microsoft packages, which share the same upgrade codes;
- stops the services and ends leftover OpenSSH processes, so an upgrade never needs a restart;
- removes the in-box Windows *OpenSSH Server*, which would otherwise take the `sshd` service back.

Older packages are refused unless you ask for a downgrade. Public installer properties are
checked before anything runs. The firewall rule opens TCP 22 on all networks on Windows Server,
and on Domain and Private networks only on Windows 10 and 11, so a laptop on public Wi-Fi does
not expose SSH. An upgrade keeps the rule's ports and networks, `SSHD_PORT=<n>` moves the server
to another port, and `ACTIVE_SESSIONS=abort` makes the install stop instead of ending open
sessions. If the install fails, the previous package comes back with its firewall settings.
From 10.5.4.0 on, the packages also install OpenSSH Server PN Manager, with Start-menu shortcuts, and
open its setup wizard after a first installation run with a window (`OPEN_WIZARD=0` turns that
off). Details: [docs/INSTALL.md](docs/INSTALL.md).

```powershell
# install (elevated)
msiexec /i .\OpenSSH-Win64-v10.5.7.0.msi /qn /norestart /l*v "$env:TEMP\openssh-install.log"

# verify
ssh -V                                  # OpenSSH_for_Windows_10.5p1 OpenSSH-Server-PN, LibreSSL 4.3.2
Get-Service sshd, ssh-agent             # Running, StartType Automatic
Test-NetConnection localhost -Port 22   # TcpTestSucceeded : True
```

## OpenSSH Server PN Manager

OpenSSH has no control panel; this project adds one. **OpenSSH Server PN Manager** is a single
executable (`OpenSSHServerPNManager.exe`, .NET Framework 4.5 or later), installed by the packages
of 10.5.4.0 and later and running from any folder as well. Up to version 1.6.0,
released with 10.5.2.0 and earlier, it was called OpenSSH Server Manager (`OpenSSHServerManager.exe`);
version 2.0.0 takes over its preferences, rules and firewall block list:

- **Setup wizard**: port and networks, a key for you (made in the wizard, or the `.pub` file of
  one you have), key-only login for administrators or everyone, the recommended settings and who
  may log in, in five steps. Start it from the Dashboard, the Key generator tab, the Start menu, the notification
  area icon, or with `OpenSSHServerPNManager.exe --wizard`.
- **Dashboard**: service state, version, listeners, sessions, SFTP, firewall, host key fingerprints;
  start, stop, restart, test the configuration, add your public key, generate host keys.
- **Sessions**: live connections with user, start time, duration, peer address and what they do
  (SFTP, scp, shell or command); disconnect.
- **Settings** and **sshd_config (text)**: form and full-text editing. Every save shows the
  changes first, warns when your own account would be refused, is checked with `sshd -t`, never
  writes over a file changed meanwhile, and keeps a backup (with a browser to compare and restore
  them). After a restart the server is checked and you confirm the new settings; without an
  answer within 60 seconds the previous ones come back.
- **Authentication**: tick how accounts log in: Windows authentication (the Windows password),
  public key, Kerberos on domain members, or key and password together. Add rules for single
  users or groups, for example public key only for administrators. See which methods any account
  gets before you apply. *Apply* warns before you would lock yourself out and then checks the
  result with the running server.
- **SFTP**: switch SFTP on or off and log every file transfer in the event log. Keep SFTP-only
  accounts and groups: they transfer files and nothing else, optionally confined to a folder they
  see as `/` (one per account with `%u`), optionally download only; *Apply* creates the folders.
  Tested with real transfers and escape attempts (`--authtest`).
- **Partners**: SFTP accounts for customers, suppliers and auditors, each in a folder of its own,
  after a one-time setup that never has to touch `sshd_config` again. Create one with a generated
  password shown once, download-only access, key-only login or a last day; reset its password,
  disable, unlock, manage its keys, delete it. *Transfers* lists every upload, download, rename
  and refused request by period and account, exports CSV and makes an HTML report.
- **Alerts**: e-mail (SMTP) and webhook (Microsoft Teams, Slack and others) when `sshd` stops,
  failed logins pile up, a partner's files arrive or the disk runs low, and a monthly transfer
  report; automatic blocking of addresses with many failed logins (1 hour, 24 hours, 7 days),
  never the allow list or a logged-in session. Two scheduled tasks run it as SYSTEM, with no
  service of their own.
- **Keys**: administrator and per-user `authorized_keys` with fingerprints and the ACLs `sshd`
  requires; comments in the files are kept.
- **Key generator**: creates Ed25519, ECDSA, RSA and post-quantum ML-DSA key pairs, verifies
  every key, authorizes it for your account on this server if you ask, and tests a login with it.
  Loads the keys you have (OpenSSH, PuTTY `.ppk`, PEM), changes, adds or removes their passphrase,
  and exports them for PuTTY, WinSCP and FileZilla (`.ppk` versions 3 and 2) or as OpenSSH and
  RFC 4716 files; a `.ppk` key is converted to OpenSSH when it is loaded. Passphrases never appear
  on a command line, and conversions happen in memory.
- **Client**: your `known_hosts` (add a server's keys after comparing fingerprints),
  the hosts of `.ssh\config`, and the keys in `ssh-agent`.
- **Firewall**: rule state, profiles and ports.
- **Logs**: the OpenSSH event log by period, with filters and export, SFTP transfers; failed logins by client
  address, with a firewall block list; the file log.
- **Hardening**: 28 checks (29 with SFTP-only accounts), including a security audit of the permissions on the program folder,
  the configuration and host keys, the registry and the services, and whether SSH is reachable
  on a public network. Fix the selected warnings, or apply all recommended settings; export the
  report.
- **About**: version, publisher and licence, the paths and versions of the server, links to this
  project's website, updates and support, and *Copy details* for a problem report.
- Dark mode and high contrast, keyboard shortcuts, and an icon in the notification area that
  reports when `sshd` stops or failed logins pile up.

`--check`, `--unittest`, `--selftest`, `--keytest`, `--authtest` and `--screenshot` run the same code
unattended. See [tools/OpenSSH-Server-PN-Manager/README.md](tools/OpenSSH-Server-PN-Manager/README.md).

![OpenSSH Server PN Manager: SFTP partners](docs/images/manager-partners.png)

![OpenSSH Server PN Manager: SFTP-only accounts](docs/images/manager-sftp.png)

![OpenSSH Server PN Manager: login methods](docs/images/manager-authentication.png)

![OpenSSH Server PN Manager: key generator](docs/images/manager-keygen.png)

## Supported Windows versions

| Windows | x86 | x64 | ARM64 | Terminal |
|---|---|---|---|---|
| Windows 11, Windows Server 2022 / 2025 | yes | yes | yes | ConPTY |
| Windows 10 1809+, Windows Server 2019 | yes | yes | yes | ConPTY |
| Windows 10 before 1809, Windows Server 2016 | yes | yes | no | `ssh-shellhost` fallback |
| Windows 8.1, Windows Server 2012 / 2012 R2 | yes | yes | no | `ssh-shellhost` fallback |
| Windows 7 SP1, Windows Server 2008 R2 | yes | yes | no | `ssh-shellhost` fallback |

Windows Server Core is supported (silent `msiexec` install). Windows Server is x64 only; use the
Win64 package there. [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) has the evidence and the
known limitations.

## Historical verification: 10.5.4.0

- The CI built the release from the tag `v10.5.4.0` (2026-09-27, run 36320527427) and ran all 767
  OpenSSH unit tests on x64, x86 and ARM64, none failed.
- It installed the packages on Windows Server 2022 and 2025 (x64) and on Windows 11 on ARM
  (ARM64), and a fourth time on Windows Server 2022 with the installer's steps on the Windows
  PowerShell 2.0 engine of Windows 7 and Server 2008 R2. On each machine it ran install, upgrade
  with the firewall settings kept, repair, a failed installation rolled back, refused and allowed
  downgrade with `SSHD_PORT`, `ACTIVE_SESSIONS` with a key login open, uninstall with the manager's
  scheduled tasks set up (they were removed), and a first installation with a window, after which
  the manager opened its setup wizard as the installing user. The installed manager was the
  committed build, with both Start-menu shortcuts. After the install it ran OpenSSH Server PN
  Manager's `--check`, `--selftest` (122 tests), `--keytest` (every key type, with a login) and
  `--authtest`: the Authentication tab's settings with real logins; SFTP with real transfers, where
  an SFTP-only account stayed confined to its folder; five partner tests (password and key-only
  partners, download only, disable and enable, the last day, a new password, delete); and the
  agent (an address blocked and unblocked, the transfer archive, the Watch task as SYSTEM, the
  uninstall step). That was 275 checks per machine and 280 with PowerShell 2.0, none failed; on
  Windows Server 2022 the job passed on its second attempt, after the test's own temporary `sshd`
  service could not be stopped once between two settings. The upstream Pester end-to-end tests:
  159 passed, 0 failed, 1 skipped.
- The libraries are those of 10.5.3.0, whose x64 `libcrypto.dll` encrypts with AES-128-GCM at
  4.66 GB/s, where 10.5.2.0's managed 0.2 GB/s (`openssl speed`, Windows 11 Pro, 2026-09-27).
- The installer of the earlier builds was also tested by hand on Windows 11 Pro. That covered
  upgrade with open sessions, same-version replacement, blocked and allowed downgrade, switching
  architecture, install from inside an SSH session, adding and removing features, repair,
  uninstall, firewall profiles and rejected property values. After each install: automatic
  service start, public-key login, and recovery after `Restart-Service sshd` and after a forced
  kill of `sshd.exe`. The owner installed the 10.5.3.0 package on Windows Server 2008 R2 (the
  machine where the installation of 10.5.1.0 had hung), Windows Server 2019, Windows Server 2025
  and Windows 11, and it passed on each (2026-09-27).
- Not tested yet: the 10.5.4.0 packages on machines outside the CI (the owner's Windows Server
  2008 R2, 2019 and 2025 and Windows 11), a double-click installation with a user's own UAC
  prompt, Windows 7, 8.1 and Windows Server 2012 and 2016 themselves, a restart with the new
  package installed, and Kerberos logins.

The full record, including what could not be tested here, is in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Install, upgrade, keys, configuration, hardening, uninstall, troubleshooting |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Windows version and architecture matrix, evidence, limitations |
| [docs/SFTP-PERFORMANCE.md](docs/SFTP-PERFORMANCE.md) | SFTP speed: what 10.5.3.0 changed, the fastest client settings, how to measure your server |
| [docs/BUILDING.md](docs/BUILDING.md) | Build and package from `src/` for x64, x86 and ARM64; updating OpenSSH and the libraries |
| [docs/RELEASING.md](docs/RELEASING.md) | How a release is made: tag, CI build and tests, draft release, SBOM, attestations, signing and preview policy |
| [packaging/intune/README.md](packaging/intune/README.md) | Deploying with Intune or Configuration Manager: commands, detection rule, return codes |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Every build: changes and verification |
| [docs/COMPARISON-BITVISE.md](docs/COMPARISON-BITVISE.md) | Feature audit against Bitvise SSH Server and other commercial servers |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned improvements |
| [tools/OpenSSH-Server-PN-Manager/README.md](tools/OpenSSH-Server-PN-Manager/README.md) | The management console |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to propose changes |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, and the security design of the packages |

Issues with this project go to its [issue tracker](https://github.com/patnawa/openssh_server_pn/issues).

## License and credits

OpenSSH is developed by the OpenBSD project and distributed under BSD-style licences; the Windows
port is copyright Microsoft Corporation under the same terms. `src/LICENCE` has the full text, and
every package ships `LICENSE.txt` and `NOTICE.txt` (third-party notices for LibreSSL, libfido2,
libcbor and zlib) in its install folder. The additions of this project (installer logic,
OpenSSH Server PN Manager, documentation), copyright © 2026 patnawa, are provided under the same terms.
