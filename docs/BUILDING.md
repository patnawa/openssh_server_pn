# Building OpenSSH Server PN from source

This guide describes the procedure that was used to build and package versions 10.2.0.0 to
10.5.1.0 on 2026-09-25, for x64, x86 and ARM64, from the `src/` folder of this repository. The
source follows the layout of the Windows port of OpenSSH, which manages its crypto and
compression libraries through a [vcpkg](https://github.com/microsoft/vcpkg) manifest.
The older wiki pages that download prebuilt LibreSSL and zlib archives describe a previous layout
and no longer apply.

Everything below was run on Windows 11 Pro (build 26200), x64, with PowerShell 7. Commands that
must run elevated are marked **(admin)**.

## 1. Prerequisites

| Component | Version used | Notes |
|---|---|---|
| Visual Studio 2022 Build Tools | 17.14 (MSVC 14.44, Windows SDK 10.0.26100) | Workload *Desktop development with C++*, plus the **Spectre-mitigated** runtime libraries. The vcpkg triplets compile every dependency with `/Qspectre`, which needs them. |
| ARM64 components (optional) | same | `VC.Tools.ARM64` and `VC.Runtimes.ARM64.Spectre`, only for ARM64 packages. |
| Git for Windows | 2.5x | Must be on `PATH`. |
| vcpkg | master (baseline pinned in `vcpkg.json`) | Cloned and bootstrapped once; `vcpkg integrate install` is required because the `.vcxproj` files use vcpkg's MSBuild integration. |
| WiX Toolset | 3.14.1 | The `wix314-binaries.zip` archive is enough; no installer required. WiX 4/5 is not compatible with `openssh.wixproj`. |
| PowerShell 7 (`pwsh`) | 7.x | The helper scripts in `.github/tools` target PowerShell 7. |

Install the compiler with winget (one command, unattended):

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-package-agreements --accept-source-agreements `
  --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre"
```

Add the ARM64 pieces later if you need them **(admin)**. Close every `MSBuild.exe` first, or the
installer exits with code 8006 (process blocking):

```powershell
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe" modify `
  --installPath "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools" `
  --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre --quiet --norestart
```

## 2. Layout

The source lives in `src/`, with the build helper scripts in `src/.github/tools`. The repository
history starts on 26 September 2026. The earlier history, including upstream OpenSSH's, is not in
the repository; the maintainer keeps it in the git bundle
`openssh_server_pn-history-2026-09-26.bundle`, because merging a new OpenSSH release needs it (see
below). The helper scripts look for
vcpkg in `$env:VCPKG_ROOT` or in a `vcpkg` folder next to `src`, so use this layout:

```
C:\src\openssh_server_pn\
  src\                  # server and client source, installer (src\contrib\win32\install)
  vcpkg\                # vcpkg clone (git-ignored)
  tools\wix314\         # unpacked WiX 3.14 binaries (git-ignored)
  tools\OpenSSH-Server-Manager\
  docs\
```

```powershell
cd C:\src
git clone https://github.com/patnawa/openssh_server_pn.git
cd openssh_server_pn
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg; .\bootstrap-vcpkg.bat -disableMetrics; .\vcpkg.exe integrate install; cd ..
Invoke-WebRequest https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip -OutFile wix314-binaries.zip
Expand-Archive wix314-binaries.zip -DestinationPath tools\wix314
```

All commands below that say `cd C:\src\openssh_server_pn\src` mean the `src` folder of this
repository.

A new OpenSSH release is merged in a clone of the history bundle, where `git subtree` finds the
earlier merges; the merged `src` then comes back into this repository as one commit:

```powershell
cd C:\src
git clone openssh_server_pn-history-2026-09-26.bundle openssh-history   # once; keep it for the next release
cd openssh-history
# 1. Give the clone this repository's current src.
robocopy C:\src\openssh_server_pn\src src /MIR
git add -A src; git commit -m "src as in openssh_server_pn"
# 2. Merge the release.
git subtree pull --prefix=src https://github.com/openssh/openssh-portable.git V_<version>
# 3. Resolve the conflicts and commit, then copy src back and commit it in this repository.
robocopy src C:\src\openssh_server_pn\src /MIR
```

Tested on 26 September 2026 with upstream `master`: the merge found its base, merged 115 files
and stopped on 5 conflicts, all in files the Windows port changes (`servconf.c`, `ssh-add.c`,
`ssh-ed25519-sk.c`, `sshconnect2.c`, `sshd-session.c`). A single-commit repository cannot do this:
without the earlier merges, `git subtree pull` has no common base.

Follow the merge rules in `src/.github/instructions/merge/`: generated files are taken from
upstream, the Windows fields of `version.h` are kept, and the regress scripts keep their CRLF
handling. After a merge, `src\.github\tools\Sync-VersionResource.ps1` resets the file version to
`<major>.<minor>.0.0`; set the third field to the build number you release.

Do not use a shallow clone for vcpkg: the manifest pins a `builtin-baseline` commit and version
overrides, and vcpkg resolves those from the repository history.

## 3. Build the dependencies

```powershell
cd C:\src\openssh_server_pn\src
.\.github\tools\Install-VcpkgDependencies.ps1 -Architecture x64        # x86, ARM64 likewise; several at once: -Architecture x64,x86,ARM64
```

This runs `vcpkg install` against `contrib/win32/openssh/vcpkg.json` with the custom triplets in
`vcpkg_triplets` and the overlay ports in `vcpkg_overlay_ports`. LibreSSL builds as a DLL
(`libcrypto.dll`), the others as static libraries. Expect about two minutes per architecture.

The script installs into `vcpkg_installed\<triplet>\<triplet>\`, the layout that MSBuild's vcpkg
integration and the projects use, and checks that `libcrypto.dll` is there. (The upstream script
let vcpkg use its flat default and then checked the nested path, so it failed on every fresh
tree; this project passes `--x-install-root`.) Do not pass `-Clean` when adding a second
architecture; it deletes the whole `vcpkg_installed` folder.

## 4. Build OpenSSH **(admin)**

```powershell
cd C:\src\openssh_server_pn\src
.\.github\tools\Start-OpenSSHBuild.ps1 -Configuration Release -Architecture x64
.\.github\tools\Start-OpenSSHBuild.ps1 -Configuration Release -Architecture x86   -AllowArchMismatch
.\.github\tools\Start-OpenSSHBuild.ps1 -Configuration Release -Architecture ARM64 -AllowArchMismatch
```

Output lands in `bin\x64\Release`, `bin\Win32\Release` and `bin\ARM64\Release`, together with
`sshd_config_default`, `moduli`, `LICENSE.txt`, `NOTICE.txt`, the PowerShell helper scripts and
`openssh-events.man`. The build log is `contrib\win32\openssh\OpenSSH<Configuration><Arch>.log`;
a clean build ends with `0 Error(s)` and a handful of `C4047` and `CS1668` warnings.

Why elevation is required: the helper module adds `%ProgramFiles%\Git\cmd` to the **machine**
`PATH` and fails with `Requested registry access is not allowed` otherwise. It also rewrites
`WindowsSDKVersion` in `contrib\win32\openssh\paths.targets` to the newest installed SDK; revert
that file before committing.

The build helpers find the source root as the folder that holds `version.h` and
`contrib\win32\openssh`. Upstream they looked for the nearest `.git` folder, which is the
repository root here, not `src`.

Do not use `Start-OpenSSHPackage` (or `AzDOBuildTools\Copy-BuildResults`) on a machine that runs
OpenSSH: it stops the `ssh-agent` service and, without elevation, loops forever trying.

## 5. Package the MSI

`contrib\win32\install\openssh.wixproj` binds its payload from `bin\<Platform>\Release`. Copy
`libcrypto.dll` (and its `.pdb`) from the vcpkg output first; for x86, mirror `bin\Win32\Release`
to `bin\x86\Release` because MSBuild and WiX disagree on the folder name.

```powershell
$repo = 'C:\src\openssh_server_pn\src'; $wix = 'C:\src\openssh_server_pn\tools\wix314\'; $ver = '10.5.1.0'
$msbuild = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"

Copy-Item "$repo\contrib\win32\openssh\vcpkg_installed\x64-custom\x64-custom\bin\libcrypto.*" "$repo\bin\x64\Release"
& $msbuild "$repo\contrib\win32\install\openssh.wixproj" /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:ProductVersion=$ver /p:WixToolPath=$wix

Copy-Item "$repo\contrib\win32\openssh\vcpkg_installed\x86-custom\x86-custom\bin\libcrypto.*" "$repo\bin\Win32\Release"
robocopy "$repo\bin\Win32\Release" "$repo\bin\x86\Release" /MIR
& $msbuild "$repo\contrib\win32\install\openssh.wixproj" /t:Rebuild /p:Configuration=Release /p:Platform=x86 /p:ProductVersion=$ver /p:WixToolPath=$wix

Copy-Item "$repo\contrib\win32\openssh\vcpkg_installed\arm64-custom\arm64-custom\bin\libcrypto.*" "$repo\bin\ARM64\Release"
& $msbuild "$repo\contrib\win32\install\openssh.wixproj" /t:Rebuild /p:Configuration=Release /p:Platform=ARM64 /p:ProductVersion=$ver /p:WixToolPath=$wix
```

The MSI is written to `contrib\win32\install\bin\<Platform>\Release\openssh.msi`; rename it to
`OpenSSH-Win64-v<ver>.msi`, `OpenSSH-Win32-v<ver>.msi` or `OpenSSH-ARM64-v<ver>.msi`.
`ProductVersion` must match `FILEVERSION` in `contrib\win32\openssh\version.rc`.

Always pass `/t:Rebuild` (as above) when you build again with a different `ProductVersion` and
no source file changed: WiX's MSBuild targets track only file inputs, so an incremental build
keeps the old `.wixobj` and produces a package with the previous version and product code.

`openssh.wixproj` embeds `contrib\win32\install\preinstall.ps1` into the package: a target
before `Compile` writes `obj\<Platform>\Release\preinstall.wxi` with the script as base64, and
`product.wxs` includes it. That script is the pre-install step described in
[INSTALL.md](INSTALL.md) section 3: it stops the services, ends processes that hold files, and
removes the in-box server. It runs through `powershell.exe` and is written for Windows PowerShell
2.0; test any change on the oldest Windows you support. One ICE check is suppressed on purpose:
ICE61, because the upgrade table covers the package's own version so that a rebuilt package
replaces the installed one. The `CNDL1077` compiler warning is suppressed too: the script
property holds PowerShell type names in square brackets, which are literal text.

Source changes to the upstream packaging, for WiX 3.14 and for server deployments:

- `client.wxs`: the `ClientPATH` component (system `PATH` entry) needs a `<CreateFolder />`
  element, or `light.exe` fails validation with `ICE18: KeyPath for Component 'ClientPATH' is
  Directory 'INSTALLFOLDER'`.
- `server.wxs`: the firewall exception was changed from `Profile="private"` to `Profile="all"`.
  Domain-joined Windows Servers run on the Domain profile, where a Private-only rule never
  applies. This matches the inbox Windows OpenSSH feature. Keep `private` if you build for
  client machines only.
- `product.wxs` (10.5.1.0): the `MajorUpgrade` element was replaced by explicit `Upgrade`
  rows for all three upgrade codes. Older and same versions are removed; a newer version of
  any architecture stops the install unless `ALLOWDOWNGRADE=1`. Each row has its own action
  property. `RemoveExistingProducts` stays right after `InstallInitialize`, as Windows Installer
  requires. The `OpenSSHPreInstall` custom action runs the embedded script directly after it:
  `WixQuietExec`, deferred, no impersonation, `Return="ignore"`, condition
  `NOT Installed OR REMOVE OR REINSTALL`. It uses 64-bit PowerShell (`System64Folder`) in the
  x64 and ARM64 packages and 32-bit PowerShell (`SystemFolder`) in the x86 package. Public
  properties `ALLOWDOWNGRADE`, `KEEP_INBOX_OPENSSH` and `FIREWALL_PROFILES` are secure custom
  properties.
- `product.wxs` (10.5.1.0): a second deferred action, `OpenSSHFirewallProfiles`, runs the same
  script right after the WiX firewall action (`After="WixSchedFirewallExceptionsInstall"`, condition
  `&Server = 3`) and sets the rule's network profiles. By default that is all profiles on Windows
  Server and Domain plus Private on client editions (`MsiNTProductType`). `FIREWALL_PROFILES`
  overrides it. Launch conditions accept only known values for `FIREWALL_PROFILES` and
  `KEEP_INBOX_OPENSSH` and refuse an apostrophe in `INSTALLFOLDER`. Those values reach a
  single-quoted PowerShell command that runs as LocalSystem, so no command-line value can change
  that command.
- Identity (10.5.1.0): product name and manufacturer *OpenSSH Server PN*, `ARPURLINFOABOUT` and
  `ARPHELPLINK` pointing at this repository, `CompanyName`, `ProductName` and `LegalCopyright` in
  `contrib\win32\openssh\version.rc`, and the banner comment `OpenSSH-Server-PN` in `version.h`.
  The upgrade codes are unchanged, so earlier builds and the official packages are still
  recognised and replaced.

The MSIs are unsigned. Sign `openssh.msi` and the executables with `signtool` if your
environment requires it.

## 6. Refreshing the vendored libraries

The versions live in `contrib\win32\openssh\vcpkg.json` (`overrides[]` and `builtin-baseline`)
and, for LibreSSL and libfido2, in the overlay ports under `vcpkg_overlay_ports`. The repository
ships a tool that performs the mechanical edits (manifest, overlay manifest, tarball SHA-512, and
the LibreSSL resource-version patch):

```powershell
.\.github\tools\Update-VcpkgPort.ps1 -Port libressl -Version 4.3.2 -Baseline <vcpkg commit> -DryRun
.\.github\tools\Update-VcpkgPort.ps1 -Port libressl -Version 4.3.2 -Baseline <vcpkg commit>
.\.github\tools\Update-VcpkgPort.ps1 -Port libfido2 -Version 1.17.0
.\.github\tools\Install-VcpkgDependencies.ps1 -Architecture x64,x86,ARM64
```

Patch hunks that vcpkg rejects must be regenerated by hand; vcpkg applies them with
`git apply --ignore-whitespace`, so test with the same flags. Drop a patch when upstream now
carries the change. Versions used for the 2026-09-25 build:

| Library | Previous | Current | Upstream release | Note |
|---|---|---|---|---|
| LibreSSL | 4.2.0 | 4.3.2 | 2026-05-26 | `aarch64-windows.diff` removed; upstream ships the identical `crypto_cpu_caps_windows.c`. |
| libfido2 | 1.16.0 | 1.17.0 | 2026-04-15 | Includes YSA-2026-01 (restricted `webauthn.dll` search path). |
| libcbor | 0.14.0 | 0.14.0 | 2026-07-18 | unchanged |
| zlib | 1.3.2 | 1.3.2 | 2026-02-17 | unchanged |
| vcpkg baseline | `a345bbdc` (2024-12-04) | `10541e31` (2026-09-25) | | Registry snapshot for helper ports (`vcpkg-cmake`, `vcpkg-cmake-config`). |

## 7. Verify an installed server

Run from an elevated PowerShell after installing the MSI. The sequence below is what the
2026-09-25 x64 package passed on Windows 11.

```powershell
# 1. Versions and services
ssh -V                                     # OpenSSH_for_Windows_10.2p1 ..., LibreSSL 4.3.2
Get-Service sshd, ssh-agent                # Running / Automatic
sc.exe qfailure sshd                       # RESTART x3, reset period 86400

# 2. Listener, banner and firewall
Get-NetTCPConnection -LocalPort 22 -State Listen
$c = New-Object Net.Sockets.TcpClient('127.0.0.1', 22); $b = New-Object byte[] 128
$n = $c.GetStream().Read($b, 0, 128); [Text.Encoding]::ASCII.GetString($b, 0, $n); $c.Close()   # SSH-2.0-OpenSSH_for_Windows_10.2
Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' | Select-Object Enabled, Profile

# 3. Key login as an administrator (temporary key, removed afterwards)
ssh-keygen -q -t ed25519 -N '' -f $env:TEMP\verify-key
Set-Content "$env:ProgramData\ssh\administrators_authorized_keys" (Get-Content "$env:TEMP\verify-key.pub")
icacls "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
ssh -i $env:TEMP\verify-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no "$env:USERNAME@127.0.0.1" whoami

# 4. Service restart and crash recovery
Restart-Service sshd; Get-Service sshd
Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId -Force; Start-Sleep 5; Get-Service sshd   # restarted by the SCM

# 5. Clean up the temporary key
Remove-Item "$env:ProgramData\ssh\administrators_authorized_keys", "$env:TEMP\verify-key", "$env:TEMP\verify-key.pub"
```

A machine reboot is the final check for "survives restart": after rebooting, `Get-Service sshd`
must report `Running` and step 2 must succeed without any manual action.

## 8. Portability checks

To confirm that a build keeps its downlevel compatibility (Windows 7 SP1 / Server 2008 R2 and
later), inspect the binaries with `dumpbin` from the Build Tools:

```powershell
$dumpbin = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
& $dumpbin /headers bin\x64\Release\sshd.exe | Select-String 'subsystem version|operating system version'   # 6.00
& $dumpbin /dependents bin\x64\Release\sshd.exe                                                           # system DLLs only, no vcruntime/ucrt
& $dumpbin /imports bin\x64\Release\sshd.exe | Select-String 'CreatePseudoConsole'                        # no static import; resolved at run time
```

`contrib\win32\openssh\targetos.manifest` declares Vista through Windows 10/11 as supported
operating systems and marks the binaries long-path aware. The MSI itself refuses to install on
anything older than Windows 7 (`VersionNT >= 601`).

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Visual Studio with required components not found` or `vswhere not found` | Build Tools missing or without the C++ workload. Re-run the winget command in section 1. |
| `Requested registry access is not allowed` | The build helper needs an elevated shell (section 4). |
| `LNK1104 ... Spectre` or missing `spectre` libraries | Install the Spectre-mitigated runtime component for the target architecture. |
| `vcpkg install ... libcrypto.dll not found` | Layout false negative, see section 3. |
| `error LGHT0103: The system cannot find the file 'sshd_config_default'` (x86) | WiX binds from `bin\x86\Release`; mirror `bin\Win32\Release` there (section 5). |
| `error LGHT0204: ICE18 ... ClientPATH` | Add `<CreateFolder />` to the `ClientPATH` component (section 5). |
| VS installer exits with 8006 | Idle `MSBuild.exe` node-reuse processes are blocking it; stop them and retry. |
| `msiexec` returns 1638 | Same version already installed. Uninstall it first (`msiexec /x {ProductCode}`); the MSI does not allow same-version upgrades. |
