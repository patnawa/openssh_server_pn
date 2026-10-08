# Deliberately changes a live test server. Never run this on a production/workstation installation.
# Child uses Windows PowerShell 5.1 to load the manager's .NET Framework assembly.
param([Parameter(Mandatory = $true)][ValidateSet('Kill', 'ArmReboot', 'VerifyReboot', 'Verify', 'Child')][string]$Phase,
      [Parameter(Mandatory = $true)][string]$FixtureDir,
      [string]$Manager = (Join-Path $env:ProgramFiles 'OpenSSH/OpenSSHServerPNManager.exe'),
      [ValidateRange(15,300)][int]$DeadlineSeconds = 45,
      [switch]$DisposableMachine)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $DisposableMachine) { throw 'Recovery fault injection requires a disposable VM and -DisposableMachine.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated inside the disposable VM.' }
$live = Join-Path $env:ProgramData 'ssh/sshd_config'
$stateFile = Join-Path $FixtureDir 'fixture.json'
function Firewall-Fingerprint {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $rows = @()
    foreach ($rule in $policy.Rules) {
        if ($rule.Name -notin 'OpenSSH SSH Server Preview (sshd)', 'OpenSSH SSH Server (sshd)') { continue }
        $values = @($rule.Name, $rule.Enabled, $rule.Profiles, $rule.Direction, $rule.Action, $rule.Protocol,
            $rule.LocalAddresses, $rule.RemoteAddresses, $rule.ApplicationName, $rule.ServiceName,
            $rule.InterfaceTypes, $rule.EdgeTraversal, $rule.Description, $rule.Grouping)
        if ($rule.Protocol -in 6,17) { $values += @($rule.LocalPorts,$rule.RemotePorts) }
        if ($rule.Protocol -in 1,58) { $values += $rule.IcmpTypesAndCodes }
        $values += ((@($rule.Interfaces) | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_)) }) -join ',')
        foreach ($name in 'EdgeTraversalOptions','LocalAppPackageId','LocalUserOwner','LocalUserAuthorizedList','RemoteUserAuthorizedList','RemoteMachineAuthorizedList','SecureFlags') {
            try { $values += $rule.$name } catch { $values += '<unsupported>' }
        }
        $rows += (($values | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_)) }) -join '|')
    }
    return (($rows | Sort-Object) -join "`n")
}
function Read-Status {
    $pending = Join-Path $env:ProgramData 'ssh/manager/recovery/pending.ini'
    $result = @{}
    if (Test-Path $pending) {
        foreach ($line in [IO.File]::ReadAllLines($pending)) {
            $parts = $line -split '=',2
            if ($parts.Count -eq 2) { $result[$parts[0]] = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1])) }
        }
    }
    return $result
}
function Assert-RecoveryTaskXml([xml]$TaskXml, [string]$ExpectedRunner) {
    $ns = New-Object Xml.XmlNamespaceManager($TaskXml.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $principals = $TaskXml.SelectNodes('/t:Task/t:Principals/t:Principal', $ns)
    $actions = $TaskXml.SelectNodes('/t:Task/t:Actions/*', $ns)
    if ($principals.Count -ne 1 -or $actions.Count -ne 1 -or $actions[0].LocalName -ne 'Exec') { throw 'Recovery must have exactly one principal and one executable action.' }
    $user = $principals[0].SelectSingleNode('t:UserId', $ns).InnerText
    $sid = if ($user -match '^S-1-') { New-Object Security.Principal.SecurityIdentifier($user) }
           else { (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]) }
    if ($sid.Value -ne 'S-1-5-18') { throw "Recovery task does not run as SYSTEM: $user" }
    if ($TaskXml.SelectSingleNode('/t:Task/t:Actions', $ns).GetAttribute('Context') -ne $principals[0].GetAttribute('id')) { throw 'Recovery action uses a different principal.' }
    $command = $actions[0].SelectSingleNode('t:Command', $ns).InnerText
    $arguments = $actions[0].SelectSingleNode('t:Arguments', $ns).InnerText
    if (-not [string]::Equals([IO.Path]::GetFullPath($command), [IO.Path]::GetFullPath($ExpectedRunner), [StringComparison]::OrdinalIgnoreCase)) { throw "Recovery does not execute the expected immutable runner: $command" }
    if ($arguments -cne '--recover-configuration') { throw "Unexpected recovery arguments: $arguments" }
    return [ordered]@{ principalSid=$sid.Value; command=$command; arguments=$arguments }
}
function Capture-RecoveryTask {
    $managerPath = (Resolve-Path -LiteralPath $Manager).Path
    $sourceBytes = [IO.File]::ReadAllBytes($managerPath)
    [byte[]]$configBytes = @()
    if (Test-Path -LiteralPath ($managerPath+'.config')) { $configBytes = [IO.File]::ReadAllBytes($managerPath+'.config') }
    $payload = New-Object byte[] ($sourceBytes.Length + $configBytes.Length)
    [Buffer]::BlockCopy($sourceBytes,0,$payload,0,$sourceBytes.Length)
    [Buffer]::BlockCopy($configBytes,0,$payload,$sourceBytes.Length,$configBytes.Length)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash($payload)).Replace('-','') } finally { $sha.Dispose() }
    $expected = Join-Path $env:ProgramData ('ssh/manager/recovery/runner/'+$digest+'/OpenSSHServerPNManager.exe')
    $xml = Export-ScheduledTask -TaskName 'Configuration recovery' -TaskPath '\OpenSSH Server PN Manager\'
    $evidence = Assert-RecoveryTaskXml ([xml]$xml) $expected
    $evidence.runnerHash = (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash
    if ($evidence.runnerHash -ne (Get-FileHash -LiteralPath $managerPath -Algorithm SHA256).Hash) { throw 'Scheduled recovery runner differs from the installed manager.' }
    $evidence.runnerConfigHash = ''
    if ($configBytes.Length -gt 0) {
        $evidence.runnerConfigHash = (Get-FileHash -LiteralPath ($expected+'.config') -Algorithm SHA256).Hash
        if ($evidence.runnerConfigHash -ne (Get-FileHash -LiteralPath ($managerPath+'.config') -Algorithm SHA256).Hash) { throw 'Scheduled recovery runtime configuration differs from the installed manager.' }
    } elseif (Test-Path -LiteralPath ($expected+'.config')) { throw 'Unexpected recovery runner configuration exists.' }
    $evidence.xmlFile = Join-Path $FixtureDir 'recovery-task.xml'
    [IO.File]::WriteAllText($evidence.xmlFile, $xml, [Text.Encoding]::Unicode)
    return $evidence
}
$script:readinessError = ''
function Assert-Restored($record) {
    $status = Read-Status
    if ($status['id'] -ne $record.transactionId) { throw 'Recovery journal belongs to a different transaction.' }
    if ($status['status'] -ne 'restored') { return $false }
    if ((Get-FileHash $live -Algorithm SHA256).Hash -ne $record.configHash) { throw 'Recovery reported success but configuration bytes differ.' }
    if ((Firewall-Fingerprint) -cne $record.firewall) { throw 'Recovery reported success but the complete firewall snapshot differs.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if ($service.State -ne 'Running' -or $service.ProcessId -le 0) { $script:readinessError = 'Recovered sshd is not running yet.'; return $false }
    # sshd reports SERVICE_RUNNING before binding its listeners. Retry transient readiness within the outer deadline.
    $tcpErrors = @()
    $ports = @(Get-NetTCPConnection -State Listen -OwningProcess $service.ProcessId -ErrorAction SilentlyContinue -ErrorVariable tcpErrors | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    if (($ports -join ',') -ne ($record.ports -join ',')) {
        $script:readinessError = "Recovered listener ports '$($ports -join ',')' do not yet match '$($record.ports -join ',')'. $($tcpErrors -join '; ')"
        return $false
    }
    if ($Phase -ne 'VerifyReboot' -and $service.ProcessId -eq $record.appliedPid) { throw 'Recovery did not restart sshd.' }
    return $true
}
if ($Phase -eq 'Child') {
    if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'The fixture child must run on Windows PowerShell 5.1.' }
    $assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path $Manager).Path)
    $flags = [Reflection.BindingFlags]'Public,Static'
    $cfgType = $assembly.GetType('OpenSSHServerPNManager.SshdConfig', $true)
    $recoveryType = $assembly.GetType('OpenSSHServerPNManager.ConfigurationRecovery', $true)
    $fwType = $assembly.GetType('OpenSSHServerPNManager.Firewall', $true)
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $record = [ordered]@{
        schemaVersion = 1; configHash = (Get-FileHash $live -Algorithm SHA256).Hash
        firewall = Firewall-Fingerprint; bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O')
        ports = @(Get-NetTCPConnection -State Listen -OwningProcess $svc.ProcessId | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    }
    $config = $cfgType.GetMethod('Load',$flags).Invoke($null,@([string]$live))
    $config.Set('LogLevel', $(if ($config.Get('LogLevel') -eq 'DEBUG1') { 'DEBUG2' } else { 'DEBUG1' }))
    $backup = $config.SaveValidated($false)
    $transaction = $recoveryType.GetMethod('Open',$flags).Invoke($null,@())
    $before = $fwType.GetMethod('CaptureForRecovery',$flags).Invoke($null,@())
    $record.deadline = [DateTime]::UtcNow.AddSeconds($DeadlineSeconds).ToString('O')
    $record.transactionId = $transaction.Arm($backup, $before, [DateTime]::Parse($record.deadline).ToUniversalTime())
    $record.task = Capture-RecoveryTask
    # Change all fields that the normal settings flow changes; the snapshot must recover the rest too.
    $fwType.GetMethod('Apply',$flags,$null,[type[]]@([bool],[int],[string]),$null).Invoke($null,@($false, [int]2, '49222')) | Out-Null
    Restart-Service sshd
    $record.appliedPid = (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId
    $record.managerHash = (Get-FileHash $Manager -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($stateFile, ($record | ConvertTo-Json -Depth 8))
    [IO.File]::WriteAllText((Join-Path $FixtureDir 'ready'), 'armed')
    # Parent ends this process, or a test VM reboot interrupts it. It must never confirm recovery.
    Start-Sleep -Seconds 1800
    exit 0
}
if ($Phase -in 'Kill','ArmReboot') {
    if (Test-Path $FixtureDir) { throw 'Use a new fixture directory for each recovery scenario.' }
    New-Item -ItemType Directory -Path $FixtureDir | Out-Null
    & icacls.exe $FixtureDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE) { throw 'Could not protect the fixture directory.' }
    $seconds = if ($Phase -eq 'ArmReboot') { 180 } else { $DeadlineSeconds }
    $ps = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Phase','Child','-FixtureDir',('"'+$FixtureDir+'"'),'-Manager',('"'+$Manager+'"'),'-DeadlineSeconds',$seconds,'-DisposableMachine')
    $child = Start-Process $ps -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $FixtureDir 'child.out') -RedirectStandardError (Join-Path $FixtureDir 'child.err')
    $limit = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path (Join-Path $FixtureDir 'ready')) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $limit) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path (Join-Path $FixtureDir 'ready'))) {
        if (-not $child.HasExited) { $child.Kill() }
        throw ('Recovery fixture did not arm: ' + (Get-Content (Join-Path $FixtureDir 'child.err') -Raw))
    }
    $child.Kill(); $child.WaitForExit()
    Write-Host "Killed fixture process $($child.Id) after applying unconfirmed settings."
    if ($Phase -eq 'ArmReboot') {
        Write-Host "Reboot this disposable VM within 180 seconds; then run -Phase VerifyReboot -FixtureDir `"$FixtureDir`" -DisposableMachine. No reboot was requested by this script."
        exit 0
    }
}
if (-not (Test-Path $stateFile)) { throw 'Missing fixture.json; run Kill or ArmReboot first.' }
$record = Get-Content $stateFile -Raw | ConvertFrom-Json
if ($record.schemaVersion -ne 1) { throw 'Unsupported recovery fixture schema.' }
if ($Phase -eq 'VerifyReboot') {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    if ($boot.ToString('O') -eq $record.bootTime) { throw 'The VM has not rebooted since the settings were armed.' }
    if ($boot -ge [DateTime]::Parse($record.deadline).ToUniversalTime()) { throw 'The reboot began after the recovery deadline; this run cannot prove recovery survived a reboot. Repeat from a clean checkpoint.' }
    if ((Get-FileHash $Manager).Hash -ne $record.managerHash) { throw 'The installed manager changed between recovery phases.' }
}
$limit = [DateTime]::UtcNow.AddMinutes(5)
while ([DateTime]::UtcNow -lt $limit) {
    if (Assert-Restored $record) {
        Write-Host 'PASS: independent recovery restored exact configuration bytes, complete firewall settings, running sshd and listener ports.'
        [IO.File]::WriteAllText((Join-Path $FixtureDir 'passed.txt'), ('Verified '+$Phase+' at '+[DateTime]::UtcNow.ToString('O')))
        exit 0
    }
    Start-Sleep -Seconds 2
}
throw ('Recovery did not complete: ' + ((Read-Status) | ConvertTo-Json -Compress) + ' ' + $script:readinessError)
