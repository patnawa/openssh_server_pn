# Disposable Windows acceptance runs

These drivers accompany the unsigned **10.5.7.0 / Manager 2.3.0** testing preview. The user has deferred
actual VM runs and has no signing identity yet. None of the VM, reboot or signature scenarios below
is claimed as passed by adding the drivers. Do not run them on the workstation or an unidentified VM.

## Required fixture

- A disposable Windows Server 2022/2025 x64 VM or Windows 11 ARM64 VM, with a named clean checkpoint
  and console access independent of SSH. Use a separate 32-bit Windows fixture for x86 OS coverage.
- An elevated PowerShell 7 session and Windows PowerShell 5.1. The latter loads the .NET Framework
  manager assembly in the recovery fixture. Task Scheduler, Windows Firewall and the in-box OpenSSH
  Server capability must be available. Provision the capability and complete its reboot before the run
  if Windows Features on Demand cannot be downloaded during testing.
- A local administrator account able to authenticate through the default administrator authorized-key
  path. No production keys, users, credentials, firewall rules or unrelated applications in the VM.
- A checkout of the **same commit** as the artifacts, the release MSI for the VM architecture, and its
  upgrade-test MSI from the same CI run. Product version is `10.5.7.0`; the fixture MSI uses `10.5.8.0`
  with the identical executable payload. Keep `manager-tested`, its hashes, and build provenance.
- No PN MSI already installed, no pending manager recovery or file-replacement transaction, and an unused state directory.
  Preserve the whole state directory and MSI logs as evidence. It contains ephemeral test private keys:
  the scripts restrict access to SYSTEM and Administrators. Dispose of the VM after collecting needed
  redacted reports.

## Full sequence with a real reboot

From the checkout root inside the VM:

```powershell
$fixture = @{
    MsiDir = 'C:\fixtures'
    Msi = 'OpenSSH-Win64-v10.5.7.0.msi'
    UpgradeMsi = 'OpenSSH-Win64-v10.5.8.0-upgradetest.msi'
    Version = '10.5.7.0'
    UpgradeVersion = '10.5.8.0'
    StateDir = 'C:\validation\pn-10.5.7.0-run1'
    DisposableMachine = $true
}
./.github/scripts/Invoke-DisposableValidation.ps1 -Phase BeforeReboot @fixture
```

This runs client-only install/repair/uninstall against a running in-box server and authenticated
session; full install; manager check/self/key/auth tests; SSH/SFTP integrity; process termination
recovery; upgrade, repair, failed-install rollback, downgrade and active-session scenarios. It then
holds the installed manager open, repairs with Restart Manager disabled, and requires **3010** plus
an actual pending file-replacement entry. Finally it arms unconfirmed configuration recovery and ends
the configuration process. The independent protected runner must survive replacement of the installed
manager during reboot.

The driver does **not** reboot the computer. Reboot the identified disposable VM through its console
within the printed recovery deadline, then reopen elevated PowerShell 7 in the same checkout and run:

```powershell
./.github/scripts/Invoke-DisposableValidation.ps1 -Phase AfterReboot @fixture
```

The second phase requires a changed OS boot time and unchanged MSI/installed payload hashes. It checks
that queued file replacement completed, the production recovery task restored the exact configuration
and complete firewall snapshot, services/listeners returned, and SSH/SFTP still work. It then uninstalls
and exercises first interactive setup plus cleanup. `validation.json` reaches `Complete` only after
all assertions pass. A missing checkpoint, missing result, or changed fixture is a failed/incomplete run.

## Focused runs and coverage limits

```powershell
./.github/scripts/Test-ClientOnly.ps1 -Msi C:\fixtures\OpenSSH-Win64-v10.5.7.0.msi -LogDir C:\logs -DisposableMachine
./.github/scripts/Test-SshInterop.ps1 -LogDir C:\logs -DisposableMachine
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase Kill -FixtureDir C:\validation\recovery-kill -DisposableMachine
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase ArmReboot -FixtureDir C:\validation\recovery-reboot -DisposableMachine
# After rebooting the disposable VM:
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase VerifyReboot -FixtureDir C:\validation\recovery-reboot -DisposableMachine
```

The recovery fixture uses reflection into the installed production `SaveValidated`, `Arm`, firewall
and task APIs. It kills only the process it created. The **actual SYSTEM task and copied recovery
runner**, not an in-process test stand-in, perform restoration.
Before applying the fixture mutation, the driver verifies the registered task's SYSTEM principal,
exact recovery arguments and content-addressed runner path, compares its executable/runtime-config
hashes with the installed payload, and saves `recovery-task.xml` plus those hashes in `fixture.json`.
Listener readiness is polled within the verification deadline because service startup can precede
socket binding. This isolates fault timing, but does
not prove the GUI click flow. Separately change a server setting in the GUI, end that GUI during its
confirmation dialog, and verify the same recovery evidence. Repeat with a reboot. Also check failure
to restart, an external configuration edit during confirmation, and cancellation/confirmation close to
the recovery deadline; external edits must be reported, never overwritten.

Hosted CI runs the client-only, focused SSH/SFTP and process-termination scenarios as required install
gates. It does not reboot hosted runners. The broader upstream Pester suite remains informational.
Manual accessibility acceptance still needs keyboard-only use, screen-reader labels and announcements,
high contrast, 200% scaling, and movement between monitors with different DPI.

## Local checks without installation

```powershell
pwsh -NoProfile -File .github/scripts/Test-InstallerFixtures.ps1
./.github/scripts/Test-ManagerBuild.ps1 -OutDir "$env:TEMP\manager-tested"
powershell.exe -NoProfile -File src/contrib/win32/install/tests/preinstall.Tests.ps1
powershell.exe -NoProfile -File src/contrib/win32/install/tests/package.Tests.ps1 -Msi <built-msi>
./.github/scripts/Test-MsiPayload.ps1 -Msi <built-msi> -ManagerDir "$env:TEMP\manager-tested" -Dark <wix314\dark.exe>
./tools/release/Test-UpstreamInventory.ps1
./tools/OpenSSH-Server-PN-Manager/Test-ConfigDump.ps1 -Sshd <built-sshd.exe>
./.github/scripts/Invoke-UnitTests.ps1 -BinPath <native-build-folder>
./.github/scripts/Test-CryptoProbes.ps1 -BinPath <native-build-folder> -RequireSuccess
```

Native unit tests use private temporary ProgramData. The `win32compat` symlink case requires elevation
or Developer Mode; report that specific limitation rather than converting it to a pass. ARM64 runtime
tests require an ARM64 host. Release signing additionally requires an owner-supplied identity; branch
builds and unsigned payload rejection checks do not prove a signed release passed.

The required crypto gate automatically uses 32-bit Windows PowerShell for x86 DLL probes on x64
Windows, so its bignum differential and elliptic-curve checks are included. Other architecture
mismatches fail the required gate rather than being counted as a pass with those probes omitted.
