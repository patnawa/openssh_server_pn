# Windows compatibility

This page records which Windows versions and architectures the packages built by this repository run
on, what that claim is based on, and where the limits are. It applies to builds 10.2.0.0 through
10.5.1.0 (2026-09-25), which share the toolchain, the Windows SDK and the minimum Windows target;
re-check it whenever the toolchain or the Windows SDK changes.

## Matrix

| Windows | Support status | x86 | x64 | ARM64 | Interactive terminal |
|---|---|---|---|---|---|
| Windows 11 (all releases) | in support | yes | yes | yes | ConPTY (native pseudo console) |
| Windows Server 2025 | in support | n/a | yes | n/a | ConPTY |
| Windows Server 2022 | in support | n/a | yes | n/a | ConPTY |
| Windows 10 1809 and later (LTSC 2019, LTSC 2021, IoT) | in support (LTSC) | yes | yes | yes | ConPTY |
| Windows Server 2019 | extended support | n/a | yes | n/a | ConPTY |
| Windows 10 before 1809, Windows Server 2016 | extended support / EOL | yes | yes | no | `ssh-shellhost.exe` fallback |
| Windows 8.1, Windows Server 2012 R2 | EOL | yes | yes | no | fallback |
| Windows 8, Windows Server 2012 | EOL | yes | yes | no | fallback |
| Windows 7 SP1, Windows Server 2008 R2 | EOL | yes | yes | no | fallback |
| Windows Vista, Server 2008, XP, 2003 | not supported | no | no | no | MSI launch condition blocks the install |

Windows Server ships for x64 only; Windows on ARM exists for Windows 10 and 11 only. Windows
Server Core and Nano Server: Server Core is supported. Nano Server is not tested and the
`ssh-shellhost` fallback depends on console components Nano lacks.

## Evidence

The matrix is derived from the following checks on the 2026-09-25 packages.

**Installer.** `product.wxs` sets the launch condition `VersionNT >= 601` (Windows 7 / Server
2008 R2) and `InstallScope="perMachine"`. The x86 and x64 MSIs declare `InstallerVersion 200`;
the ARM64 MSI is stamped `InstallerVersion 500` by WiX, as Windows Installer requires for ARM
packages. The upstream wiki states that GitHub releases "can be installed on Windows 7 and up".

**Binaries.** Checked with `dumpbin` from Visual Studio 2022 Build Tools (MSVC 14.44):

| Property | x86 | x64 | ARM64 |
|---|---|---|---|
| Machine | 14C (x86) | 8664 (x64) | AA64 (ARM64) |
| Subsystem / OS version | 6.00 | 6.00 | 6.02 |
| C runtime | static (`/MT`) | static | static |
| Imported DLLs | `kernel32`, `advapi32`, `user32`, `ws2_32`, `crypt32`, `bcrypt`, `secur32`, `userenv`, `shlwapi`, `setupapi`, `hid`, `ntdll`, `libcrypto` | same | same |
| UCRT / VCRuntime imports | none | none | none |
| Statically imported APIs newer than Windows 7 | none found in 512 distinct imports | same | not checked separately |

The compatibility manifest (`contrib/win32/openssh/targetos.manifest`) declares Windows Vista,
7, 8, 8.1 and 10 (which also covers Windows 11 and current Windows Server) as supported operating
systems and marks the binaries long-path aware. ConPTY functions (`CreatePseudoConsole` and
friends) are not statically imported; the code resolves them at run time and falls back to
`ssh-shellhost.exe` when they are missing.

**Run-time tests.**

| Test | Platform | Result |
|---|---|---|
| Install x64 MSI over official 10.0.0.0, services, key login, `Restart-Service`, forced kill of `sshd.exe` | Windows 11 Pro 26200, x64 | pass |
| x86 `ssh.exe -V`, `ssh-keygen` smoke test under WOW64 | Windows 11 Pro 26200, x64 | pass |
| ARM64 binaries | not executed (no ARM64 hardware available) | static checks only |
| Windows Server 2016 / 2019 / 2022 / 2025 | not executed in this build cycle | static checks only |
| Windows 7 / 8.1 / 10 before 1809 | not executed | static checks only |

Contributions of test results on other platforms are welcome; see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Known limitations on older Windows

- Before Windows 10 1809 / Server 2019 there is no pseudo console. Interactive sessions go
  through `ssh-shellhost.exe`, which emulates a VT100 terminal. Line editing, colours and
  full-screen console programs may misbehave; non-interactive commands, `scp` and `sftp` are
  unaffected. Details: [TTY/PTY support wiki page](https://github.com/PowerShell/Win32-OpenSSH/wiki/TTY-PTY-support-in-Windows-OpenSSH).
- `ssh-agent` and `ssh-add` work everywhere, but Windows Hello and FIDO2 security keys
  (`ssh-sk-helper`, libfido2) need Windows 10 1903 or later for the `webauthn.dll` backend.
- The PowerShell helper scripts shipped in the package require Windows PowerShell 5.1 or
  PowerShell 7. Windows 7 ships PowerShell 2.0; install WMF 5.1 there before using
  `FixHostFilePermissions.ps1` or `OpenSSHUtils.psm1`.
- The installer's pre-install step stops the services, ends leftover processes and removes the
  in-box server (INSTALL.md section 3). It is a PowerShell script embedded in the MSI and run as
  LocalSystem through Windows PowerShell of the package's bitness. It is written for Windows
  PowerShell 2.0, so it works on Windows 7 as shipped, and uses the WMI and Task Scheduler
  services, both on by default. The step never fails an install. Under a WDAC or AppLocker
  policy that forces PowerShell into constrained language mode it cannot run. The install then
  still succeeds, but an upgrade with open sessions may ask for a restart as it did before
  10.5.1.0.
- TLS-related features are not involved (SSH does not use TLS), so the LibreSSL version only
  affects the algorithms available to SSH; it does not depend on the Windows Schannel version.

## Windows Server specifics

- Domain-joined servers run on the Domain firewall profile. The rule in this repository's packages
  covers Domain, Private and Public; the official package covers Private only.
- Server Core: install silently with `msiexec`, manage with `sc.exe`, `Get-Service` and the
  `NetSecurity` PowerShell module. No GUI component is used by the package.
- Group Policy that restricts the `LocalSystem` privileges listed in [INSTALL.md](INSTALL.md)
  or enforces AppLocker / WDAC rules must allow `%ProgramFiles%\OpenSSH\*.exe`; the binaries are
  unsigned, so hash or path rules are needed.
- Windows Server with the inbox OpenSSH Server capability installed: since build 10.5.1.0 the
  installer removes the capability itself, with DISM `/Remove-Capability` logged in the MSI log,
  and keeps the `sshd.exe` process mitigation in place (INSTALL.md section 6).
  `KEEP_INBOX_OPENSSH=1` keeps the capability. Earlier builds required
  `Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` first.
