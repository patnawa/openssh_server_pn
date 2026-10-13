# Disposable Windows acceptance runs

## Candidate rebuild — 13 October 2026

Product **10.5.8.0**, with the updated **Manager 2.3.2**, was rebuilt from
[`a601cb6077b8381058c87758329c5b9d15f7eaec`](https://github.com/patnawa/openssh_server_pn/commit/a601cb6077b8381058c87758329c5b9d15f7eaec)
on branch `codex/installer-manager-validation-20261013` by
[run 38360329356](https://github.com/patnawa/openssh_server_pn/actions/runs/38360329356).
The run completed successfully: **14 jobs passed**, with the two release-only jobs intentionally
skipped. These are unsigned branch artifacts; no release was published.

- The freshly built Manager passed **315 unit tests and 49 GUI checks**, including independent
  reproducibility and LF/CRLF checkout checks. Its executable, configuration and build metadata
  match the locally tested files byte for byte.
- x64, x86 and ARM64 native builds passed. Each architecture passed **767 native tests**,
  **139 AuthorizedKeysFile configuration-dump checks**, and the required crypto probes.
- Downloaded MSI checksums matched the hosted `SHA256SUMS.txt`. Local package inspection passed
  **161 checks for x64**, **161 for x86**, and **162 for ARM64**. CAB inspection confirmed the
  exact tested Manager executable and configuration, plus all 16 required executable/DLL payloads.
- Server 2022 x64, Server 2025 x64, Server 2022 with PowerShell 2.0 and Windows 11 ARM64 passed
  **364 installed self-tests each**, `--check`, `--keytest`, `--authtest`, SSH/SFTP integrity,
  client-only coexistence, actual SYSTEM recovery after process termination, installation,
  upgrade, repair, rollback, downgrade, active-session handling, uninstall and wizard launch.
- The informational Pester suite passed **159 tests**, with **0 failures, 1 skipped and 0 pending**
  (the suite skips forced pseudo-terminal allocation with `-t`).

The packages and local inspection evidence are retained under
`dist/installer-validation-20261013/`. Package SHA-256 values:

| Package | SHA-256 |
|---|---|
| `OpenSSH-Win64-v10.5.8.0.msi` | `c9fa32e5bcd6af473f58358da19c4e487c0b161c8f4220236d0295221a44e3e5` |
| `OpenSSH-Win32-v10.5.8.0.msi` | `cef3589608006b3b6ba2fef2dfd2da0a949b843d6e34514f922716b796c353a6` |
| `OpenSSH-ARM64-v10.5.8.0.msi` | `6da69b5069a8b564b071f6f44b21cf923888316671b0b5613d3e78653b739304` |

Actual reboot and pending-file-replacement acceptance remain unrun. The workstation has WSL
Ubuntu but no registered Windows VM; Hyper-V and Windows Sandbox are disabled, and no VMware
or VirtualBox installation was found. The hosted lanes do not reboot. Physical mixed-monitor,
screen-reader, GUI-click recovery and other-account UAC acceptance remain separate manual checks.

## Previous release evidence — 9 October 2026

These drivers target **10.5.8.0 / Manager 2.3.2** at source
`ec50173df04ece893ea486aae26d385fd8d9d8c5`. Use the driver checkout and artifacts from
the same tested revision. Local manual VM/reboot acceptance remains deferred; do not
run destructive installation scenarios on the workstation or an unidentified VM.

The [hosted manager run](https://github.com/patnawa/openssh_server_pn/actions/runs/37915311314)
passed 290 unit tests, 49 GUI checks and 13 installer-fixture checks, matching the local
manager bytes. [Product run 37915311883](https://github.com/patnawa/openssh_server_pn/actions/runs/37915311883)
completed successfully: all 14 expected jobs passed, with tag-only signing/release jobs
intentionally skipped. x64/x86/ARM64 native build/unit/crypto/configuration gates and all
four installation lanes passed. Server 2022, Server 2025, PowerShell 2.0 and Windows 11
ARM64 each passed 339/339 installed self-tests, actual SYSTEM process-termination recovery,
wizard launch, client-only coexistence, authentication, SSH/SFTP, upgrade, repair, rollback
and uninstall. The release-files gate passed; informational Pester reported 159 passed,
0 failures and 1 ignored.

Regular unsigned `release-v10.5.8.0` and `release-manager-v2.3.2` were published on
**9 October 2026** from the exact accepted hosted artifacts, with **Manager Latest**.
Both regular-release flags and GitHub's Latest destination were verified. All 11 product
and 8 Manager assets were downloaded afresh before publication and publicly afterward;
all 19 hashes matched the accepted staging files.
Signing and cryptographic build attestations are not supplied by that publication path.
Manual actual-reboot/pending-file-replacement acceptance, GUI-click recovery, other-account
UAC/client identity, accessibility/multiple-monitor checks and a failed or cancelled uninstall
remain pending. The commands below describe how to exercise them; their presence is not
evidence that they passed.

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
  upgrade-test MSI from the same CI run. Product version is `10.5.8.0`; the fixture MSI uses `10.5.9.0`
  with the identical executable payload. Keep `manager-tested`, its hashes, build metadata and hosted run records.
- No PN MSI already installed, no pending manager recovery or file-replacement transaction, and an unused state directory.
  Preserve the whole state directory and MSI logs as evidence. It contains ephemeral test private keys:
  the scripts restrict access to SYSTEM and Administrators. Dispose of the VM after collecting needed
  redacted reports.

## Full sequence with a real reboot

From the checkout root inside the VM:

```powershell
$fixture = @{
    MsiDir = 'C:\fixtures'
    Msi = 'OpenSSH-Win64-v10.5.8.0.msi'
    UpgradeMsi = 'OpenSSH-Win64-v10.5.9.0-upgradetest.msi'
    Version = '10.5.8.0'
    UpgradeVersion = '10.5.9.0'
    StateDir = 'C:\validation\pn-10.5.8.0-run1'
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
./.github/scripts/Test-ClientOnly.ps1 -Msi C:\fixtures\OpenSSH-Win64-v10.5.8.0.msi -LogDir C:\logs -DisposableMachine
./.github/scripts/Test-SshInterop.ps1 -LogDir C:\logs -DisposableMachine
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase Kill -FixtureDir C:\validation\recovery-kill -DisposableMachine
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase ArmReboot -FixtureDir C:\validation\recovery-reboot -DisposableMachine
# After rebooting the disposable VM:
./.github/scripts/Test-ConfigurationRecovery.ps1 -Phase VerifyReboot -FixtureDir C:\validation\recovery-reboot -DisposableMachine
```

The recovery fixture uses reflection into the installed production `SaveValidated`, `Arm`, firewall
and task APIs. Its Windows PowerShell child prioritizes Windows PowerShell's own modules so
inherited PowerShell 7 paths cannot hide required commands such as `Get-FileHash`. It kills
only the process it created. The **actual SYSTEM task and copied recovery
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
