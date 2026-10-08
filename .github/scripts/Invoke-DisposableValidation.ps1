# Complete installer/recovery acceptance driver. This never provisions or reboots a VM itself.
param([Parameter(Mandatory = $true)][ValidateSet('BeforeReboot','AfterReboot')][string]$Phase,
      [Parameter(Mandatory = $true)][string]$MsiDir,
      [Parameter(Mandatory = $true)][string]$Msi,
      [Parameter(Mandatory = $true)][string]$UpgradeMsi,
      [Parameter(Mandatory = $true)][string]$Version,
      [Parameter(Mandatory = $true)][string]$UpgradeVersion,
      [Parameter(Mandatory = $true)][string]$StateDir,
      [switch]$DisposableMachine)
$ErrorActionPreference = 'Stop'
if (-not $DisposableMachine) { throw 'This driver changes services, accounts and firewall rules. Supply -DisposableMachine only inside an identified disposable VM.' }
$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from elevated PowerShell 7 inside the disposable VM.' }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'This driver requires PowerShell 7; recovery fixture children use Windows PowerShell 5.1.' }
$env:FIREWALL_PRESERVATION_CHECK = 'enforce'
$env:SSHD_PORT_CHECK = 'enforce'
$env:ACTIVE_SESSIONS_CHECK = 'enforce'
$stateFile = Join-Path $StateDir 'validation.json'
$logDir = Join-Path $StateDir 'logs'
$parameters = @{ MsiDir=$MsiDir; Msi=$Msi; UpgradeMsi=$UpgradeMsi; Version=$Version; UpgradeVersion=$UpgradeVersion; LogDir=$logDir }
Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force
if ($Phase -eq 'BeforeReboot') {
    if (Test-Path $StateDir) { throw 'Use a new state directory and a clean VM checkpoint for each run.' }
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    & icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE) { throw 'Cannot protect validation state.' }
    & (Join-Path $PSScriptRoot 'Test-ClientOnly.ps1') -Msi (Join-Path $MsiDir $Msi) -LogDir $logDir -DisposableMachine
    & (Join-Path $PSScriptRoot 'Test-Installer.ps1') -Scenario Install @parameters
    $manager = Get-ManagerPath
    foreach ($mode in '--check','--selftest','--keytest','--authtest') {
        if ((Invoke-ManagerTest -Exe $manager -Mode $mode -ReportDir $logDir) -ne 0) { throw "Manager $mode failed." }
    }
    & (Join-Path $PSScriptRoot 'Test-SshInterop.ps1') -LogDir $logDir -DisposableMachine
    & (Join-Path $PSScriptRoot 'Test-ConfigurationRecovery.ps1') -Phase Kill -FixtureDir (Join-Path $StateDir 'recovery-kill') -DisposableMachine
    foreach ($scenario in 'Upgrade','Repair','Rollback','Downgrade','Sessions') {
        & (Join-Path $PSScriptRoot 'Test-Installer.ps1') -Scenario $scenario @parameters
    }
    & (Join-Path $PSScriptRoot 'Test-PendingReboot.ps1') -Phase Arm -Msi (Join-Path $MsiDir $UpgradeMsi) -StateDir (Join-Path $StateDir 'pending-reboot') -DisposableMachine
    $state = [ordered]@{
        schemaVersion=1; phase='AwaitingReboot'; machine=$env:COMPUTERNAME
        bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O')
        msiHash=(Get-FileHash (Join-Path $MsiDir $Msi) -Algorithm SHA256).Hash
        upgradeHash=(Get-FileHash (Join-Path $MsiDir $UpgradeMsi) -Algorithm SHA256).Hash
        installedVersion=(Get-InstalledOpenSSHProduct).DisplayVersion
        managerHash=(Get-FileHash $manager -Algorithm SHA256).Hash
    }
    [IO.File]::WriteAllText($stateFile, ($state | ConvertTo-Json))
    & (Join-Path $PSScriptRoot 'Test-ConfigurationRecovery.ps1') -Phase ArmReboot -FixtureDir (Join-Path $StateDir 'recovery-reboot') -DisposableMachine
    Write-Host 'Pre-reboot scenarios passed. Reboot this disposable VM now; rerun the same command with -Phase AfterReboot.'
    exit 0
}
if (-not (Test-Path $stateFile)) { throw 'No recorded pre-reboot validation state.' }
$state = Get-Content $stateFile -Raw | ConvertFrom-Json
if ($state.schemaVersion -ne 1 -or $state.phase -ne 'AwaitingReboot' -or $state.machine -ne $env:COMPUTERNAME) { throw 'Validation state belongs to another machine, schema or completed run.' }
if ($state.bootTime -eq (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O')) { throw 'A real VM reboot is required before this phase.' }
if ($state.msiHash -ne (Get-FileHash (Join-Path $MsiDir $Msi)).Hash -or $state.upgradeHash -ne (Get-FileHash (Join-Path $MsiDir $UpgradeMsi)).Hash) { throw 'The MSI fixtures changed between phases.' }
if ($state.managerHash -ne (Get-FileHash (Get-ManagerPath)).Hash -or $state.installedVersion -ne (Get-InstalledOpenSSHProduct).DisplayVersion) { throw 'The installed payload changed between phases.' }
& (Join-Path $PSScriptRoot 'Test-PendingReboot.ps1') -Phase Verify -StateDir (Join-Path $StateDir 'pending-reboot') -DisposableMachine
& (Join-Path $PSScriptRoot 'Test-ConfigurationRecovery.ps1') -Phase VerifyReboot -FixtureDir (Join-Path $StateDir 'recovery-reboot') -DisposableMachine
foreach ($service in 'sshd','ssh-agent') { if ((Get-Service $service).Status -ne 'Running') { throw "$service did not start after reboot." } }
& (Join-Path $PSScriptRoot 'Test-SshInterop.ps1') -LogDir $logDir -DisposableMachine
foreach ($scenario in 'Uninstall','FirstRun') { & (Join-Path $PSScriptRoot 'Test-Installer.ps1') -Scenario $scenario @parameters }
$state.phase = 'Complete'
$state | Add-Member -NotePropertyName completedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('O'))
[IO.File]::WriteAllText($stateFile, ($state | ConvertTo-Json))
Write-Host "PASS: complete installer, fault-recovery and reboot validation. Evidence: $StateDir"
