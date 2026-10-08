# Forces Windows Installer's delayed file replacement in a disposable VM, without rebooting it.
param([Parameter(Mandatory = $true)][ValidateSet('Arm','Verify','Lock')][string]$Phase,
      [Parameter(Mandatory = $true)][string]$StateDir,
      [string]$Msi,
      [string]$Target = (Join-Path $env:ProgramFiles 'OpenSSH/OpenSSHServerPNManager.exe'),
      [switch]$DisposableMachine)
$ErrorActionPreference = 'Stop'
if (-not $DisposableMachine) { throw 'Pending-reboot fault injection requires -DisposableMachine inside an isolated VM.' }
$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated inside the disposable VM.' }
$recordPath = Join-Path $StateDir 'pending-reboot.json'
function Pending-Operations {
    $item = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    return @($item.PendingFileRenameOperations)
}
function Pending-TargetOperations([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    return @(Pending-Operations | Where-Object { $_ -and $_.EndsWith($absolute, [StringComparison]::OrdinalIgnoreCase) })
}
if ($Phase -eq 'Lock') {
    $stream = [IO.File]::Open($Target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try { [IO.File]::WriteAllText((Join-Path $StateDir 'locked'), 'ready'); Start-Sleep -Seconds 1800 }
    finally { $stream.Dispose() }
    exit 0
}
if ($Phase -eq 'Arm') {
    if (-not $Msi -or -not (Test-Path $Msi)) { throw 'The installed package MSI is required for forced repair.' }
    if (Test-Path $StateDir) { throw 'Use a new state directory for pending-reboot validation.' }
    if (@(Pending-TargetOperations $Target).Count) { throw 'This target already has pending replacement operations; restore a clean VM checkpoint before this fixture.' }
    New-Item -ItemType Directory -Path $StateDir | Out-Null
    & icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE) { throw 'Could not protect pending-reboot state.' }
    $record = [ordered]@{ schemaVersion=1; bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O'); target=$Target; hash=(Get-FileHash $Target).Hash }
    $hostPath = (Get-Process -Id $PID).Path
    $child = Start-Process $hostPath -ArgumentList @('-NoProfile','-File',('"'+$PSCommandPath+'"'),'-Phase','Lock','-StateDir',('"'+$StateDir+'"'),'-Target',('"'+$Target+'"'),'-DisposableMachine') -PassThru -WindowStyle Hidden
    $limit = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path (Join-Path $StateDir 'locked')) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $limit) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path (Join-Path $StateDir 'locked'))) { if (-not $child.HasExited) { $child.Kill() }; throw 'Could not hold the fixture file open.' }
    try {
        Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force
        $code = Invoke-Msiexec -Arguments @('/fa',('"'+$Msi+'"'),'MSIRESTARTMANAGERCONTROL=Disable','REBOOT=ReallySuppress') -LogPath (Join-Path $StateDir 'repair-locked.log') -AllowedExitCodes 0,3010
        $pending = @(Pending-TargetOperations $Target)
        if ($code -ne 3010 -or $pending.Count -eq 0) { throw "The fixture did not produce pending replacement: exit=$code, matching operations=$($pending.Count)." }
        $record.exitCode=$code; $record.operations=$pending; $record.lockPid=$child.Id
        [IO.File]::WriteAllText($recordPath,($record | ConvertTo-Json -Depth 5))
        Write-Host "PASS: repair returned 3010 and queued replacement of the locked manager. Reboot the VM; lock process $($child.Id) remains running until then."
    } catch { if (-not $child.HasExited) { $child.Kill() }; throw }
    exit 0
}
$record = Get-Content $recordPath -Raw | ConvertFrom-Json
if ($record.schemaVersion -ne 1) { throw 'Unsupported pending-reboot fixture schema.' }
if ($record.bootTime -eq (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O')) { throw 'The VM has not rebooted.' }
if ((Get-FileHash $record.target).Hash -ne $record.hash) { throw 'Payload hash changed across delayed file replacement.' }
if (@(Pending-TargetOperations $record.target).Count) { throw 'Delayed manager replacement is still pending after reboot.' }
[IO.File]::WriteAllText((Join-Path $StateDir 'passed.txt'),'Verified pending replacement at '+[DateTime]::UtcNow.ToString('O'))
Write-Host 'PASS: reboot consumed the pending file replacement and preserved the tested manager bytes.'
