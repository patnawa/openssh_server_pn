# Non-elevated regression checks for explicit compiler selection.
# powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/OpenSSH-Server-PN-Manager/build.Tests.ps1
$ErrorActionPreference = 'Stop'
$build = Join-Path $PSScriptRoot 'build.ps1'
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('openssh-build-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testDir
$failed = 0
try {
    $outDir = Join-Path $testDir 'output'
    $missing = Join-Path $testDir 'missing-csc.exe'
    $message = ''
    try { & $build -Csc $missing -OutDir $outDir } catch { $message = $_.Exception.Message }
    if ($message -eq "No compiler at $missing") { Write-Output 'PASS: missing explicit compiler is rejected' }
    else { $failed++; Write-Output "FAIL: missing explicit compiler was ignored ($message)" }

    # A probe compiler stops before compilation and reports the output argument that the build
    # passed it. This exercises compiler dispatch without relying on Visual Studio being installed.
    $probe = Join-Path $testDir 'compiler-probe.ps1'
    [IO.File]::WriteAllText($probe, 'throw ("compiler-probe: " + (($args | Where-Object { $_ -like "/out:*" }) -join ";"))')
    $message = ''
    try { & $build -Csc $probe -ReferenceDir $testDir -OutDir $outDir } catch { $message = $_.Exception.Message }
    $expected = 'compiler-probe: /out:' + (Join-Path $outDir 'OpenSSHServerPNManager.exe')
    if ($message -eq $expected) { Write-Output 'PASS: explicit compiler is invoked with the requested output path' }
    else { $failed++; Write-Output "FAIL: explicit compiler was not invoked ($message)" }

    $lock = Get-Content (Join-Path $PSScriptRoot 'build-toolchain.json') -Raw | ConvertFrom-Json
    $cached = Join-Path $testDir ($lock.packages[0].id + '.' + $lock.packages[0].version + '.nupkg')
    [IO.File]::WriteAllText($cached, 'tampered compiler archive')
    $message = ''
    try { & (Join-Path $PSScriptRoot 'Restore-Toolchain.ps1') -Cache $testDir -Destination (Join-Path $testDir 'restore') } catch { $message = $_.Exception.Message }
    if ($message -like 'Cached package hash mismatch:*') { Write-Output 'PASS: changed cached toolchain archive is rejected before extraction' }
    else { $failed++; Write-Output "FAIL: cached toolchain integrity was not checked ($message)" }
} finally {
    # testDir is a freshly generated direct child of the system temporary directory.
    $resolved = [IO.Path]::GetFullPath($testDir)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected test directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
if ($failed -gt 0) { throw "$failed compiler-selection checks failed" }
