# Focused gating E2E suite. Requires the installed package on a disposable elevated Windows VM.
param([Parameter(Mandatory = $true)][string]$LogDir,
      [switch]$DisposableMachine)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $DisposableMachine) { throw 'Run this test only on a disposable VM.' }
Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force
$bin = Get-OpenSSHInstallDir
$dir = Join-Path $LogDir ('interop-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$authorized = Join-Path $env:ProgramData 'ssh/administrators_authorized_keys'
$savedKeys = if (Test-Path $authorized) { [IO.File]::ReadAllBytes($authorized) } else { $null }
$session = $null
try {
    $key = New-AdminTestKey -Dir $dir
    $port = @(Get-SshdListenPort) | Select-Object -First 1
    if (-not $port) { throw 'The installed sshd has no listener.' }
    $session = Start-TestSshSession -KeyPath $key -Port $port -Dir $dir
    Write-Host 'PASS: installed client authenticates to the installed server and executes a remote command.'
    $known = Join-Path $dir 'known_hosts'
    $random = New-Object Random 18421
    $batch = New-Object 'System.Collections.Generic.List[string]'
    $checks = @()
    foreach ($size in @(0, 1, 65536)) {
        $source = Join-Path $dir ("input-$size.bin")
        $remote = Join-Path $dir ("remote space-$size.bin")
        $download = Join-Path $dir ("download-$size.bin")
        $bytes = New-Object byte[] $size
        $random.NextBytes($bytes)
        [IO.File]::WriteAllBytes($source, $bytes)
        foreach ($command in @(
            ('put "' + $source.Replace('\','/') + '" "' + $remote.Replace('\','/') + '"'),
            ('get "' + $remote.Replace('\','/') + '" "' + $download.Replace('\','/') + '"'),
            ('rm "' + $remote.Replace('\','/') + '"'))) { $batch.Add($command) }
        $checks += @{ Source = $source; Download = $download; Size = $size }
    }
    $batchPath = Join-Path $dir 'sftp.txt'
    [IO.File]::WriteAllLines($batchPath, $batch, (New-Object Text.UTF8Encoding $false))
    # Start-TestSshSession captured the host key. Subsequent operations must use that exact trust.
    $options = '-b "' + $batchPath + '" -i "' + $key + '" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="' + $known + '" -P ' + $port + ' ' + $env:USERNAME + '@127.0.0.1'
    $result = Invoke-Native -FilePath (Join-Path $bin 'sftp.exe') -Arguments $options -TimeoutSeconds 90
    [IO.File]::WriteAllText((Join-Path $dir 'sftp.log'), $result.Output)
    if ($result.ExitCode -ne 0) { throw "SFTP roundtrip failed: $($result.Output)" }
    foreach ($check in $checks) {
        if (-not (Test-Path $check.Download) -or (Get-FileHash $check.Source).Hash -ne (Get-FileHash $check.Download).Hash) { throw "SFTP corrupted or lost the $($check.Size)-byte file." }
        Write-Host "PASS: $($check.Size)-byte SFTP upload/download with a spaced remote path preserved SHA-256."
    }
    if ($session.HasExited) { throw 'Independent SSH session was interrupted during file transfers.' }
} finally {
    if ($session -and -not $session.HasExited) { $session.Kill() }
    if ($null -ne $savedKeys) { [IO.File]::WriteAllBytes($authorized, $savedKeys) } else { Remove-Item -LiteralPath $authorized -ErrorAction SilentlyContinue }
}
