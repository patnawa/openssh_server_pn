# OpenSSH Server PN

**OpenSSH Server PN** is an OpenSSH server and client for Windows with its own installer and a
management console. It builds on OpenSSH 10.5p1 and the Windows port of OpenSSH, and adds an
installer that cleans up whatever was installed before, a GUI with a setup wizard, a key-pair
generator and security checks, and a firewall rule that stays off public networks on Windows 10
and 11. Windows password logins stay on after installation, as in the official package, until
you have set up keys; the manager's setup wizard switches them off for administrators.

| Folder | Contents |
|---|---|
| `src/` | The server and client source: OpenSSH 10.5p1 with the Windows port, the vendored-library manifest (LibreSSL 4.3.2, libfido2 1.17.0) and the WiX installer. The repository history starts on 26 September 2026; the earlier history, with upstream OpenSSH's, is kept outside the repository for merging new OpenSSH releases ([BUILDING.md](docs/BUILDING.md#2-layout)) |
| `tools/OpenSSH-Server-PN-Manager/` | [OpenSSH Server PN Manager](tools/OpenSSH-Server-PN-Manager/README.md), the management console (C# source, build script, the built executable) |
| `docs/` | Installation, compatibility, building, releasing, changelog, feature audit and roadmap |
| `.github/`, `tools/release/` | CI (build, unit and install tests of the packages, the management console), release tooling (SBOM, upstream version check) |
| `packaging/` | winget manifests and Intune / Configuration Manager deployment notes |

This project is independent: it is not affiliated with Microsoft or the OpenBSD OpenSSH project.

## Current build: 10.5.3.0 (2026-09-27)

| Package | Target | Size | SHA-256 |
|---|---|---|---|
| `OpenSSH-Win64-v10.5.3.0.msi` | Windows x64: every Windows Server edition, 64-bit Windows 10 and 11 | 6.6 MB | `ABE05A74E68C76ED051CABB7E86A8209F61770384431B4494FEBA45C76C0E920` |
| `OpenSSH-Win32-v10.5.3.0.msi` | Windows x86: 32-bit Windows client editions | 5.9 MB | `C6C3645808FFA49455A9FA6C1FE488AFC1A838D8CC0D28DCDE496C85296BBAA6` |
| `OpenSSH-ARM64-v10.5.3.0.msi` | Windows 10 and 11 on ARM | 6.4 MB | `C8255A5A0A91FC26E49A29528606E56744570BE319830A55C58C461575BA5E3C` |
| `OpenSSHServerPNManager.exe` (2.0.0) | Management console, any Windows with .NET Framework 4.x, all architectures | 871 KB | `E6CDF9BF6DA7A958731E498372CBBE1F84426B3EE96B6D0A47713C8672C968F8` |

10.5.3.0 replaces 10.5.2.0. **SFTP, and every connection with an AES cipher, is about 3.5 times as
fast on x64**: LibreSSL built with Visual Studio never detected the processor's AES-NI and
carry-less multiplication, so AES ran on slow table code; the x64 packages use them now
(`msvc-x64-cpu-caps.patch`, [docs/BUILDING.md](docs/BUILDING.md#6-refreshing-the-vendored-libraries)).
A 512 MiB SFTP transfer over the loopback, MB/s up / down (the median of three runs, averaged over
two interleaved rounds):

| Cipher | 10.5.2.0 | 10.5.3.0 |
|---|---|---|
| `aes128-gcm@openssh.com` | 154 / 160 | 487 / 597 |
| `aes256-gcm@openssh.com` | 122 / 126 | 502 / 499 |
| `aes256-ctr` | 143 / 144 | 500 / 472 |
| `chacha20-poly1305@openssh.com` | 296 / 280 | 291 / 325 |

WinSCP and FileZilla use AES by default, so they gain without a change. OpenSSH clients choose
`chacha20-poly1305@openssh.com` first; `-c aes128-gcm@openssh.com` makes them use AES.
[docs/SFTP-PERFORMANCE.md](docs/SFTP-PERFORMANCE.md) has the settings for each client and a test
for your own server. The management console is now **OpenSSH Server PN Manager 2.0.0**, with an SFTP tab (see below). The
installer is the one of 10.5.2.0, which repaired the ARM64 package and the installation on Windows 7
and Windows Server 2008 R2 of 10.5.1.0 and earlier
([docs/INSTALL.md](docs/INSTALL.md#a-hung-installation) says how to end such an installation).
Details in [docs/CHANGELOG.md](docs/CHANGELOG.md) and [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md#run-time-tests).

Download them from the release [v10.5.3.0](https://github.com/patnawa/openssh_server_pn/releases/tag/v10.5.3.0), together with
`OpenSSHServerPNManager.exe.config` (keep it next to the executable), `SHA256SUMS.txt` and the SBOM
`OpenSSH-Server-PN-v10.5.3.0.cdx.json`. The management console also has releases of its own; the newest is
[manager-v2.1.0](https://github.com/patnawa/openssh_server_pn/releases/tag/manager-v2.1.0) (keys: load, change the passphrase, export for PuTTY; the setup wizard creates one). The files are **unsigned**: always compare
the SHA-256 hash before installing (`Get-FileHash .\OpenSSH-Win64-v10.5.3.0.msi`, or the check in
[docs/INSTALL.md](docs/INSTALL.md#1-choose-a-package)). `gh attestation verify <file> --repo patnawa/openssh_server_pn`
shows that a file was built by this repository's workflow. Anyone can rebuild them with
[docs/BUILDING.md](docs/BUILDING.md). Installed, the product appears as *OpenSSH Server PN* in
*Apps & features*, and the server identifies itself as `SSH-2.0-OpenSSH_for_Windows_10.5 OpenSSH-Server-PN`.

What is in this build:

| Component | Version | Note |
|---|---|---|
| OpenSSH | 10.5p1, file version 10.5.3.0 | Three releases ahead of the Windows port's `latestw_all` branch (10.2p1). How the 10.3, 10.4 and 10.5 releases were merged is in the changelog |
| LibreSSL | 4.3.2 (2026-05-26) | The official 10.0.0.0 Windows package shipped 4.2.0, without AES-NI. x64: with the CPU detection for Visual Studio builds, so AES-NI and PCLMULQDQ are used. ARM64: with LibreSSL's workaround for the compiler defect ([libressl/portable#1403](https://github.com/libressl/portable/issues/1403)) |
| libfido2 | 1.17.0 (2026-04-15) | Includes YSA-2026-01 (restricted `webauthn.dll` search path) |
| libcbor, zlib | 0.14.0, 1.3.2 | |
| Installer | WiX 3.14 | Removes whatever is installed first; see below |

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
Details: [docs/INSTALL.md](docs/INSTALL.md).

```powershell
# install (elevated)
msiexec /i .\OpenSSH-Win64-v10.5.3.0.msi /qn /norestart /l*v "$env:TEMP\openssh-install.log"

# verify
ssh -V                                  # OpenSSH_for_Windows_10.5p1 OpenSSH-Server-PN, LibreSSL 4.3.2
Get-Service sshd, ssh-agent             # Running, StartType Automatic
Test-NetConnection localhost -Port 22   # TcpTestSucceeded : True
```

## OpenSSH Server PN Manager

OpenSSH has no control panel; this project adds one. **OpenSSH Server PN Manager** is a single
executable (`OpenSSHServerPNManager.exe`, .NET Framework 4.x, no installation). Up to version 1.6.0,
released with 10.5.2.0 and earlier, it was called OpenSSH Server Manager (`OpenSSHServerManager.exe`);
version 2.0.0 takes over its preferences, rules and firewall block list:

- **Setup wizard**: port and networks, a key for you (made in the wizard, or the `.pub` file of
  one you have), key-only login for administrators or everyone, the recommended settings and who
  may log in, in five steps. Start it from the Dashboard, the Key generator tab, the notification
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

## Verification of this build

- The CI built the release from the tag `v10.5.3.0` (2026-09-27, run 36304755653) and ran all 767
  OpenSSH unit tests on x64, x86 and ARM64, none failed.
- It installed the packages on Windows Server 2022 and 2025 (x64) and on Windows 11 on ARM
  (ARM64), and a fourth time on Windows Server 2022 with the installer's steps on the Windows
  PowerShell 2.0 engine of Windows 7 and Server 2008 R2. On each machine it ran install, upgrade
  with the firewall settings kept, repair, a failed installation rolled back, refused and allowed
  downgrade with `SSHD_PORT`, `ACTIVE_SESSIONS` with a key login open, and uninstall. After the
  install it ran OpenSSH Server PN Manager's `--check`, `--selftest` (96 tests), `--keytest` (every
  key type, with a login) and `--authtest`: the Authentication tab's settings with real logins, and
  SFTP with real transfers, where an SFTP-only account stayed confined to its folder (`cd ..`,
  `/../..`, a drive letter and an upload outside were refused, and so were commands), a
  download-only group could not change anything, and SFTP off refused every session. That was 209
  checks per machine and 213 with PowerShell 2.0, none failed. The upstream Pester end-to-end tests:
  159 passed, 0 failed, 1 skipped.
- The x64 `libcrypto.dll` of the release encrypts with AES-128-GCM at 4.66 GB/s, where 10.5.2.0's
  managed 0.2 GB/s (`openssl speed`, Windows 11 Pro, 2026-09-27); the SFTP figures above were measured
  on the same machine.
- The installer of the earlier builds was also tested by hand on Windows 11 Pro. That covered
  upgrade with open sessions, same-version replacement, blocked and allowed downgrade, switching
  architecture, install from inside an SSH session, adding and removing features, repair,
  uninstall, firewall profiles and rejected property values. After each install: automatic
  service start, public-key login, and recovery after `Restart-Service sshd` and after a forced
  kill of `sshd.exe`.
- The owner installed the release package on Windows Server 2008 R2 (the machine where the
  installation of 10.5.1.0 had hung), Windows Server 2019, Windows Server 2025 and Windows 11, and
  it passed on each (2026-09-27), as 10.5.2.0 had on the Windows Server 2008 R2 machine.
- Not tested: Windows 7, 8.1 and Windows Server 2012 and 2016 themselves, a restart with the new
  package installed, and Kerberos logins.

The full record, including what could not be tested here, is in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Install, upgrade, keys, configuration, hardening, uninstall, troubleshooting |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Windows version and architecture matrix, evidence, limitations |
| [docs/SFTP-PERFORMANCE.md](docs/SFTP-PERFORMANCE.md) | SFTP speed: what 10.5.3.0 changed, the fastest client settings, how to measure your server |
| [docs/BUILDING.md](docs/BUILDING.md) | Build and package from `src/` for x64, x86 and ARM64; updating OpenSSH and the libraries |
| [docs/RELEASING.md](docs/RELEASING.md) | How a release is made: tag, CI build and tests, draft release, SBOM, attestations, optional signing |
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
