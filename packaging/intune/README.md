# Deploying with Intune or Configuration Manager

The packages are ordinary per-machine MSIs, so they deploy like any other Windows Installer package.
This page lists the values to enter; the installer's behaviour itself is described in
[docs/INSTALL.md](../../docs/INSTALL.md), which is the reference for everything below. The examples use
the release 10.5.1.0; replace the version, file name and product code for another build.

## Package and architecture

| Devices | Package | Intune requirement (operating system architecture) |
|---|---|---|
| 64-bit Windows 10 and 11, Windows Server | `OpenSSH-Win64-v10.5.1.0.msi` | x64 |
| Windows 10 and 11 on ARM | `OpenSSH-ARM64-v10.5.1.0.msi` | ARM64 |
| 32-bit Windows 10 | `OpenSSH-Win32-v10.5.1.0.msi` | x86 |

Only one of the three can be installed on a device: they register the same services, and each removes
the others. The packages are not Authenticode-signed; check the SHA-256 against `SHA256SUMS.txt` of the
release before you upload them, and see [Application control](#application-control).

## Intune: Win32 app

A Win32 app (a `.intunewin` file made with the
[Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
from a folder that holds the MSI) supports the install properties, the return codes and the detection
rules below. The *Windows app (MSI) line-of-business* type also takes the MSI directly, with command-line
arguments, but detects it only by product code.

```powershell
IntuneWinAppUtil.exe -c .\OpenSSH-Win64 -s OpenSSH-Win64-v10.5.1.0.msi -o .\out
```

| Setting | Value |
|---|---|
| Install command | `msiexec /i "OpenSSH-Win64-v10.5.1.0.msi" /qn /norestart /l*v "%ProgramData%\Microsoft\IntuneManagementExtension\Logs\OpenSSH-Server-PN-install.log"` |
| Uninstall command | `msiexec /x {D8B0B4AB-3605-4CC0-BB6F-72562287F36A} /qn /norestart` (the product code of the package, see below) |
| Install behavior | System |
| Device restart behavior | Determine behavior based on return codes |
| Return codes | the defaults: `0` success, `1707` success, `3010` soft reboot, `1641` hard reboot, `1618` retry |

The log folder in the install command is the one Intune's *Collect diagnostics* picks up; any folder
works. The installer needs no restart for a normal install or upgrade: it stops the services and ends
leftover OpenSSH processes first. When that cleanup cannot run (for example under a policy that forces
PowerShell into constrained language mode), Windows Installer falls back to its own handling of files in
use and may ask for a restart with `3010` (docs/INSTALL.md, section 3). Removing the in-box OpenSSH Server
can also leave a restart pending (docs/INSTALL.md, section 6). `1618` means another installation is
running; Intune retries it.

A failed install returns `1603`. The MSI log then says why; the causes specific to this package are an
older package over a newer one without `ALLOWDOWNGRADE=1`, and a `FIREWALL_PROFILES` or
`KEEP_INBOX_OPENSSH` value the installer does not accept (docs/INSTALL.md, sections 2 and 3). Nothing is
changed in either case.

### Detection rule

Either of these:

| Rule type | Value |
|---|---|
| MSI | Product code of the deployed package (below). Every build has its own product code, so each version needs its own app or rule. Optionally *Value: Greater than or equal to* the product version. |
| File | Path `%ProgramFiles%\OpenSSH`, file `sshd.exe`, detection method *String (version)*, operator *Greater than or equal to*, value `10.5.1.0`; *Associated with a 32-bit app on 64-bit clients*: No. `sshd.exe` carries the package's file version (`FILEVERSION` in `version.rc`). |

The file rule also sees an OpenSSH installed by another package in the same folder, for example
Microsoft's MSI (10.0.0.0 at the time of writing, below this package's version). The product code rule
sees only this package.

Product codes of the release 10.5.1.0 (read from the MSIs):

| Package | ProductCode |
|---|---|
| `OpenSSH-Win64-v10.5.1.0.msi` | `{D8B0B4AB-3605-4CC0-BB6F-72562287F36A}` |
| `OpenSSH-Win32-v10.5.1.0.msi` | `{2C699E59-F250-46AD-BA88-6C64EC38EC7B}` |
| `OpenSSH-ARM64-v10.5.1.0.msi` | `{36A6216C-7F01-470B-9245-93F26824134D}` |

To read the product code of another build (the MSI is opened read-only):

```powershell
$msi = (Resolve-Path .\OpenSSH-Win64-v10.5.1.0.msi).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($msi, 0))
$view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property='ProductCode'"))
$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
$record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
```

On a device where the package is installed, the product code is the name of the key under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` whose `DisplayName` is `OpenSSH Server PN`.
The CI build of every package also lists its product code in the run summary.

### Upgrades

Deploy the new version as a new app that **supersedes** the old one, without *Uninstall previous
version*: the new MSI removes the installed package itself inside the same transaction and rolls back to
it if the install fails (docs/INSTALL.md, section 3). The upgrade ends open SSH sessions, so schedule it
outside working hours on servers people log in to. `%ProgramData%\ssh` (configuration, host keys, logs)
is kept.

## Installer properties

Add them to the install command, for example
`msiexec /i "OpenSSH-Win64-v10.5.1.0.msi" ADDLOCAL=Server FIREWALL_PROFILES=domain /qn /norestart`.
The table is taken from docs/INSTALL.md, section 2, which is authoritative for the build you deploy:

| Property | Default | Effect |
|---|---|---|
| `ADDLOCAL=Client` | both | Client tools only |
| `ADDLOCAL=Server` | both | Server only (plus the shared tools) |
| `ADD_PATH=0` | `1` | Do not add `%ProgramFiles%\OpenSSH` to the system `PATH` |
| `INSTALLFOLDER=<path>` | `%ProgramFiles%\OpenSSH` | Alternate install folder (no apostrophe). The file detection rule must use the same folder |
| `ALLOWDOWNGRADE=1` | unset | Replace an installed newer package with this one |
| `KEEP_INBOX_OPENSSH=1` | unset | Leave the in-box Windows *OpenSSH Server* capability installed |
| `FIREWALL_PROFILES=` | by edition | `all`, `domain,private`, `domain` or `private`. Unset: all networks on Windows Server, Domain and Private on Windows 10 and 11 |

In 10.5.1.0 an upgrade recreates the firewall rule with these defaults, so give `FIREWALL_PROFILES`
again in the upgrade's install command if you use another setting.

## Configuration Manager

Create an application with a *Windows Installer (\*.msi file)* deployment type from the MSI. Configuration
Manager fills in the product code for detection and the uninstall command. Then:

| Setting | Value |
|---|---|
| Installation program | `msiexec /i "OpenSSH-Win64-v10.5.1.0.msi" /qn /norestart /l*v "%WINDIR%\Temp\OpenSSH-Server-PN-install.log"` |
| Installation behavior | Install for system |
| Logon requirement | Whether or not a user is logged on |
| Return codes | the defaults for MSI deployment types (`0`, `1707`, `3010`, `1641`, `1618`) |
| Requirements | Operating system architecture as in the table at the top |

For a newer version, add an application that supersedes the old one, without uninstalling it (see
[Upgrades](#upgrades)).

## Checking a deployed device

```powershell
Get-Service sshd, ssh-agent | Select-Object Name, Status, StartType    # Running / Automatic
(Get-Item "$env:ProgramFiles\OpenSSH\sshd.exe").VersionInfo.FileVersion
Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' | Select-Object Enabled, Profile
```

`OpenSSHServerManager.exe --check report.txt` (from the release, run elevated) writes a status report and
exits with 0 when the server is healthy, which suits a remediation or compliance script.

## Application control

The binaries are unsigned. Under AppLocker or WDAC, allow `%ProgramFiles%\OpenSSH\*.exe` and
`libcrypto.dll` with path or hash rules; hash rules change with every build. The installer's pre-install
step is PowerShell embedded in the MSI and run as SYSTEM. Under a policy that forces PowerShell into
constrained language mode it cannot run: the install still succeeds, but an upgrade with open sessions may
then ask for a restart (docs/COMPATIBILITY.md, *Known limitations on older Windows*).
