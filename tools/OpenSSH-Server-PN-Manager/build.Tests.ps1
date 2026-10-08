# Non-elevated regression checks for compiler selection and portable deterministic inputs.
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

    # Capture inputs once so concurrent unrelated work cannot create different fixture sources.
    $texts = @{}
    foreach ($file in Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object { $_.Extension -in '.cs','.ps1','.json' -or $_.Name -eq 'app.manifest' }) {
        $texts[$file.Name] = [IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n").Replace("`r","`n")
    }
    $iconBytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'icon/app.ico'))
    $outputs = @()
    foreach ($style in 'lf','crlf') {
        $checkout = Join-Path $testDir $(if ($style -eq 'lf') { 'checkout-lf' } else { 'different checkout with spaces CRLF' })
        New-Item -ItemType Directory -Path (Join-Path $checkout 'icon') -Force | Out-Null
        foreach ($name in $texts.Keys) {
            $content = if ($style -eq 'lf') { $texts[$name] } else { $texts[$name].Replace("`n","`r`n") }
            [IO.File]::WriteAllText((Join-Path $checkout $name),$content,(New-Object Text.UTF8Encoding ($style -eq 'crlf')))
        }
        [IO.File]::WriteAllBytes((Join-Path $checkout 'icon/app.ico'),$iconBytes)
        $output = Join-Path $checkout 'output'
        & (Join-Path $checkout 'build.ps1') -OutDir $output
        $outputs += $output
    }
    $different = @('OpenSSHServerPNManager.exe','OpenSSHServerPNManager.exe.config','build-info.json' | Where-Object {
        (Get-FileHash (Join-Path $outputs[0] $_)).Hash -ne (Get-FileHash (Join-Path $outputs[1] $_)).Hash
    })
    if ($different.Count) { $failed++; Write-Output ('FAIL: LF/CRLF, BOM and checkout-root variants differ: '+($different -join ', ')) }
    else { Write-Output 'PASS: LF/no-BOM and CRLF/BOM checkouts at different paths produce identical EXE/config/build metadata' }
} finally {
    # testDir is a freshly generated direct child of the system temporary directory.
    $resolved = [IO.Path]::GetFullPath($testDir)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected test directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
if ($failed -gt 0) { throw "$failed compiler-selection checks failed" }
