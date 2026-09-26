# Windows compatibility

This page records which Windows versions and architectures the packages built by this repository run
on, what that claim is based on, and where the limits are. It applies to builds 10.2.0.0 through
10.5.1.0 (2026-09-25), which share the toolchain, the Windows SDK and the minimum Windows target;
re-check it whenever the toolchain or the Windows SDK changes.

## Matrix

| Windows | Support status | x86 | x64 | ARM64 | Interactive terminal |
|---|---|---|---|---|---|
| Windows 11 (all releases) | in support | yes | yes | yes* | ConPTY (native pseudo console) |
| Windows Server 2025 | in support | n/a | yes | n/a | ConPTY |
| Windows Server 2022 | in support | n/a | yes | n/a | ConPTY |
| Windows 10 1809 and later (LTSC 2019, LTSC 2021, IoT) | in support (LTSC) | yes | yes | yes* | ConPTY |
| Windows Server 2019 | extended support | n/a | yes | n/a | ConPTY |
| Windows 10 before 1809, Windows Server 2016 | extended support / EOL | yes | yes | no | `ssh-shellhost.exe` fallback |
| Windows 8.1, Windows Server 2012 R2 | EOL | yes | yes | no | fallback |
| Windows 8, Windows Server 2012 | EOL | yes | yes | no | fallback |
| Windows 7 SP1, Windows Server 2008 R2 | EOL | yes† | yes† | no | fallback |
| Windows Vista, Server 2008, XP, 2003 | not supported | no | no | no | MSI launch condition blocks the install |

\* ARM64: not with the 10.5.1.0 package, whose `sshd` cannot start (see the run-time tests below); the builds after it carry the fix, verified on ARM64 hardware on 2026-09-26.

† Windows 7 and Windows Server 2008 R2 with the Windows PowerShell 2.0 they ship with (no WMF 3.0 or later): the installer of 10.5.1.0 and earlier hangs at its first PowerShell step ([INSTALL.md, *A hung installation*](INSTALL.md#a-hung-installation), reported on Windows Server 2008 R2 on 2026-09-26). The builds after it start PowerShell with `-InputFormat None`, and the CI runs every install scenario with the installer's steps on the PowerShell 2.0 engine (see *Known limitations* below).

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
| OpenSSH unit tests, all 767 (`unittest-*.exe`, x64 and x86 builds of the source after 10.5.1.0) | Windows Server 2022 Datacenter 20348 (GitHub `windows-2022`), 2026-09-26 | pass |
| Install of the x64 MSI, then upgrade (firewall rule kept at port 2222 / Private), repair, rollback of a failed installation (rule and previous package restored), refused and allowed downgrade with `SSHD_PORT=2200`, `ACTIVE_SESSIONS=abort` and `close` with a key login open, uninstall; OpenSSH Server Manager `--check`, `--selftest` (86 tests), `--keytest` (every key type), `--authtest` (nine login-method settings with real logins) | Windows Server 2022 Datacenter 20348 and Windows Server 2025 (GitHub `windows-2022`, `windows-2025`), 2026-09-26, source after 10.5.1.0 | pass (182 checks per machine) |
| ARM64 binaries of 10.5.1.0 (built 2026-09-25) | Windows 11 Enterprise 26200 on ARM64 (GitHub `windows-11-arm`), 2026-09-26 | **fail**: `unittest-sshbuf` and `unittest-hostkeys` crash at the first elliptic-curve operation, `unittest-kex` and `unittest-sshkey` hang, the MSI install ends with error 1920 because `sshd` never reports itself started (it generates the host keys first). Cause: the Visual Studio 2022 ARM64 optimizer emits an arithmetic instead of a logical shift in LibreSSL's `bn_ct_ne_zero()` once it is inlined, so the constant-time masks of the Montgomery multiplication are wrong and every EC, RSA and DH operation fails ([libressl/portable#1403](https://github.com/libressl/portable/issues/1403); fixed in Visual Studio 2026 v18.8.2). The overlay port now applies LibreSSL's workaround (`msvc-arm64-bn-ct-ne-zero.patch`, from their pull/1355); see the next row |
| ARM64 binaries and MSI of the source after 10.5.1.0, with the LibreSSL workaround | Windows 11 Enterprise 26200 on ARM64 (GitHub `windows-11-arm`), 2026-09-26 | **pass**: all 767 unit tests; every crypto probe (curves P-256/384/521, ECDSA and RSA generation) fine; install in 101 s, OpenSSH Server Manager `--check`, `--selftest` (86 tests), `--keytest`, `--authtest`; upgrade with the firewall rule kept, repair, rollback of a failed installation, downgrade with `SSHD_PORT=2200`, `ACTIVE_SESSIONS=abort` and `close`, uninstall: 195 checks, none failed. The first ARM64 build of this project that runs |
| `powershell.exe` 2.0 and 5.1, 64-bit and 32-bit, started with a standard input pipe that stays open (as `WixQuietExec` starts it) | Windows Server 2022 with the Windows PowerShell 2.0 Engine (GitHub `windows-2022`), 2026-09-26 | 2.0: **hangs** (killed after 30 s); with `-InputFormat None` exits in 0.2 s. 5.1: exits in either case, unless the command uses `$input` |
| The x64 package without `-InputFormat None` (first `v10.5.2.0` tag run), steps on PowerShell 2.0 (`-Version 2`), as on Windows 7 / Server 2008 R2 | same | **hangs** at its first step; a second `msiexec` returns 1618; ending `powershell.exe` four times lets it finish with exit 0 and nothing missing. The recovery in INSTALL.md, section 8 |
| The same package with `-InputFormat None`, steps on PowerShell 2.0: install, uninstall, and install over Microsoft's `OpenSSH-Win64-v10.0.0.0.msi` | same | pass: 6 s, 1 s and 6 s; the Private network of Microsoft's rule kept |
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
- The installer's steps stop the services, end leftover processes and remove the in-box server
  (INSTALL.md section 3), and carry the firewall settings over an upgrade. They are PowerShell
  scripts embedded in the MSI and run as LocalSystem through Windows PowerShell of the package's
  bitness. They are written for Windows PowerShell 2.0, the version Windows 7 and Windows Server
  2008 R2 ship with, and use the WMI and Task Scheduler services, both on by default. Windows
  Installer starts them with a standard input that stays open, and PowerShell 2.0 waits for its
  end: the packages up to 10.5.1.0 hang there at their first step (INSTALL.md, section 8,
  *A hung installation*). The packages after 10.5.1.0 start PowerShell with `-InputFormat None`,
  which PowerShell 2.0 needs, and the CI runs every install scenario with the steps on the
  PowerShell 2.0 engine (Windows Server 2022 with the feature *Windows PowerShell 2.0 Engine*).
  PowerShell 3.0 and later are not affected.
- The steps never fail an install. Where they cannot run, the install still succeeds, but an
  upgrade with open sessions may ask for a restart as it did before 10.5.1.0, and the firewall
  rule stays as the package creates it (port 22, all networks): `FIREWALL_PROFILES`, `SSHD_PORT`
  and the settings of the old rule are not applied. That is the case under
  a WDAC or AppLocker policy that forces PowerShell into constrained language mode, and on a
  Server Core installation of Windows Server 2008 R2 without the Windows PowerShell feature,
  which has no `powershell.exe`.
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
