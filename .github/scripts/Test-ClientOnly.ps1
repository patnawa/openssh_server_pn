# Installs packages and an in-box server. Run ONLY on a disposable, elevated Windows VM.
param([Parameter(Mandatory = $true)][string]$Msi,
      [Parameter(Mandatory = $true)][string]$LogDir,
      [switch]$DisposableMachine)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $DisposableMachine) { throw 'This scenario requires a disposable VM; pass -DisposableMachine only there.' }
Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force
if (Get-InstalledOpenSSHProduct) { throw 'Client-only coexistence requires a VM without the PN MSI installed.' }
$inbox = Join-Path $env:SystemRoot 'System32/OpenSSH'
$capability = 'OpenSSH.Server~~~~0.0.1.0'
if ((Get-WindowsCapability -Online -Name $capability).State -ne 'Installed') {
    $added = Add-WindowsCapability -Online -Name $capability
    if ($added.RestartNeeded) { throw 'The VM needs a reboot after provisioning the in-box server; provision it before this scenario.' }
}
Start-Service sshd
$beforeService = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if ($beforeService.PathName -notlike '*System32\OpenSSH\sshd.exe*') { throw 'sshd is not the in-box server.' }
$dir = Join-Path $LogDir 'client-only'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$authorized = Join-Path $env:ProgramData 'ssh/administrators_authorized_keys'
$savedKeys = if (Test-Path $authorized) { [IO.File]::ReadAllBytes($authorized) } else { $null }
$session = $null
try {
    $key = New-AdminTestKey -Dir $dir -BinDir $inbox
    $port = @(Get-SshdListenPort) | Select-Object -First 1
    $session = Start-TestSshSession -KeyPath $key -Port $port -Dir $dir -BinDir $inbox
    $protected = @(Get-ChildItem (Join-Path $env:ProgramData 'ssh') -File | Where-Object { $_.Name -eq 'sshd_config' -or $_.Name -like 'ssh_host_*' })
    $hashes = @{}; foreach ($file in $protected) { $hashes[$file.FullName] = (Get-FileHash $file.FullName).Hash }
    function Assert-ServerPreserved([string]$phase) {
        $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        if ($service.State -ne 'Running' -or $service.ProcessId -ne $beforeService.ProcessId -or $service.PathName -ne $beforeService.PathName) { throw "$phase changed the in-box server service or process." }
        if ($session.HasExited) { throw "$phase disconnected the authenticated SSH session." }
        if ((Get-WindowsCapability -Online -Name $capability).State -ne 'Installed') { throw "$phase removed the in-box server capability." }
        foreach ($file in $hashes.Keys) { if ((Get-FileHash $file).Hash -ne $hashes[$file]) { throw "$phase changed $file" } }
        Write-Host "PASS: $phase preserved the server process, capability, configuration, host keys and authenticated session."
    }
    Invoke-Msiexec -Arguments @('/i', ('"' + $Msi + '"'), 'ADDLOCAL=Client', 'ACTIVE_SESSIONS=abort') -LogPath (Join-Path $dir 'install.log') -AllowedExitCodes 0,3010 | Out-Null
    Assert-ServerPreserved 'Client-only install'
    if (-not (Test-Path (Get-ManagerPath))) { throw 'Client-only installation omitted the client GUI.' }
    $shortcut = @(Get-ManagerShortcut | Where-Object { $_.Arguments -eq '--client' })
    if ($shortcut.Count -ne 1 -or -not (Test-Path $shortcut[0].Path)) { throw 'Client workspace shortcut is missing.' }
    foreach ($serverShortcut in @(Get-ManagerShortcut | Where-Object { $_.Arguments -ne '--client' })) {
        if (Test-Path $serverShortcut.Path) { throw 'Client-only installation created a server administration shortcut.' }
    }
    Invoke-Msiexec -Arguments @('/fa', ('"' + $Msi + '"'), 'ACTIVE_SESSIONS=abort') -LogPath (Join-Path $dir 'repair.log') -AllowedExitCodes 0,3010 | Out-Null
    Assert-ServerPreserved 'Client-only repair'
    Invoke-Msiexec -Arguments @('/x', (Get-InstalledOpenSSHProduct).ProductCode) -LogPath (Join-Path $dir 'uninstall.log') -AllowedExitCodes 0,3010 | Out-Null
    Assert-ServerPreserved 'Client-only uninstall'
} finally {
    if ($session -and -not $session.HasExited) { $session.Kill() }
    if ($null -ne $savedKeys) { [IO.File]::WriteAllBytes($authorized, $savedKeys) } else { Remove-Item -LiteralPath $authorized -ErrorAction SilentlyContinue }
}
