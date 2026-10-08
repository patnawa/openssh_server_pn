param([Parameter(Mandatory = $true)][string]$OutDir,
      [switch]$TestOnly)
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot '../../tools/OpenSSH-Server-PN-Manager'
if (-not $TestOnly) {
    & (Join-Path $tool 'build.Tests.ps1')
    & (Join-Path $tool 'build.ps1') -OutDir $OutDir
    $repeat = Join-Path ([IO.Path]::GetTempPath()) ('manager-repeat-' + [guid]::NewGuid().ToString('N'))
    try {
        & (Join-Path $tool 'build.ps1') -OutDir $repeat
        foreach ($name in 'OpenSSHServerPNManager.exe', 'OpenSSHServerPNManager.exe.config', 'build-info.json') {
            if ((Get-FileHash (Join-Path $OutDir $name)).Hash -ne (Get-FileHash (Join-Path $repeat $name)).Hash) {
                throw "Reproducibility failure: $name differs between two clean builds with the pinned inputs."
            }
        }
        Write-Host 'PASS: two independent builds produced identical executable, configuration and build metadata.'
    } finally {
        $resolved = [IO.Path]::GetFullPath($repeat)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected repeat build directory: $resolved" }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}
$exe = Join-Path $OutDir 'OpenSSHServerPNManager.exe'
$report = Join-Path $OutDir 'unittest.txt'
if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
$process = Start-Process -FilePath $exe -ArgumentList @('--unittest', ('"' + $report + '"')) -PassThru -WindowStyle Hidden
if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'Manager unit tests timed out after two minutes.' }
if (-not (Test-Path -LiteralPath $report)) { throw 'Manager produced no unit-test report.' }
Get-Content -LiteralPath $report
if ($process.ExitCode -ne 0) { throw "Manager unit tests failed (exit $($process.ExitCode))." }

$uiDir = Join-Path $OutDir 'ui'
$uiReport = Join-Path $uiDir 'ui-report.txt'
if (Test-Path -LiteralPath $uiReport) { Remove-Item -LiteralPath $uiReport -Force }
$process = Start-Process -FilePath $exe -ArgumentList @('--uitest', ('"' + $uiDir + '"')) -PassThru -WindowStyle Hidden
if (-not $process.WaitForExit(300000)) { $process.Kill(); throw 'Manager UI tests timed out after five minutes.' }
if (-not (Test-Path -LiteralPath $uiReport)) { throw 'Manager produced no UI-test report.' }
Get-Content -LiteralPath $uiReport
if ($process.ExitCode -ne 0) { throw "Manager UI tests failed (exit $($process.ExitCode))." }
