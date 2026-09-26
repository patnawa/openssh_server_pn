<#
.SYNOPSIS
    Runs the OpenSSH unit tests (unittest-*.exe) of one build output folder and reports the count.

.DESCRIPTION
    Does what Invoke-OpenSSHUnitTest in src/contrib/win32/openssh/OpenSSHTestHelper.psm1 does, without
    the rest of that module's test environment (test accounts, test service, Pester):
    every unittest-<name> folder under -BinPath holds unittest-<name>.exe and its test data (copied
    there by the project's post-build step), and each binary runs with that folder as the working
    directory. The test helper prints "<n> tests ok" at the end of a passing binary; the counts are
    summed (the 10.5.0.0 build passed 767 tests in 8 binaries).

    The test helper (regress/unittests/test_helper/test_helper.c) copies <BinPath>\moduli to
    %ProgramData%\ssh\moduli when that file is missing and exits with 255 when it cannot: without
    administrator rights on a machine with an OpenSSH server, or on a machine without
    %ProgramData%\ssh. The win32compat layer reads %ProgramData% from the environment, so by default
    each binary gets a private, empty ProgramData folder. This needs no administrator rights and
    leaves the machine's %ProgramData%\ssh alone. -UseSystemProgramData runs the binaries against the
    real one instead (elevated), as the maintainers' Invoke-OpenSSHUnitTest does.

    unittest-win32compat creates a symbolic link (file_tests.c), which needs administrator rights or
    Developer Mode; without them it stops at test 39 with "ASSERT_INT_EQ(symlink_ret, 0) failed". The
    other seven binaries (686 tests in 10.5.1.0) pass without elevation. GitHub's runners are elevated.

    Exit code 0 when every binary exited with 0 and reported its count, 1 otherwise. Runs on Windows
    PowerShell 5.1 and PowerShell 7.

.PARAMETER BinPath
    Build output folder, e.g. src\bin\x64\Release or src\bin\Win32\Release.

.PARAMETER Label
    Name for the report, e.g. the architecture. Default: the name of the folder above -BinPath.

.PARAMETER TimeoutMinutes
    Time limit per binary. Default 10.

.PARAMETER UseSystemProgramData
    Run against the machine's %ProgramData% instead of a private empty one.

.EXAMPLE
    .\.github\scripts\Invoke-UnitTests.ps1 -BinPath .\src\bin\x64\Release
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinPath,

    [string]$Label = '',

    [int]$TimeoutMinutes = 10,

    [switch]$UseSystemProgramData
)

$ErrorActionPreference = 'Stop'
$BinPath = (Resolve-Path -LiteralPath $BinPath).Path
if (-not $Label) { $Label = Split-Path (Split-Path $BinPath -Parent) -Leaf }

$folders = @(Get-ChildItem -LiteralPath $BinPath -Directory -Filter 'unittest-*' | Sort-Object Name)
if ($folders.Count -eq 0) { throw "No unittest-* folders under $BinPath" }
if (-not (Test-Path -LiteralPath (Join-Path $BinPath 'moduli'))) { Write-Warning "$BinPath has no moduli file; the test helper copies it to %ProgramData%\ssh and fails without it." }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not elevated: unittest-win32compat needs administrator rights or Developer Mode for its symbolic link test.' }

$programData = $null
if (-not $UseSystemProgramData) {
    $programData = Join-Path ([IO.Path]::GetTempPath()) ('openssh-unittest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $programData 'ssh') -Force | Out-Null
    Write-Host "ProgramData for the tests: $programData"
}

$results = @()
try {
    foreach ($folder in $folders) {
        $exe = Join-Path $folder.FullName ($folder.Name + '.exe')
        if (-not (Test-Path -LiteralPath $exe)) {
            $results += [pscustomobject]@{ Binary = $folder.Name; ExitCode = $null; Tests = 0; Seconds = 0; Passed = $false; Note = 'executable missing' }
            continue
        }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.WorkingDirectory = $folder.FullName
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        if ($programData) { $psi.EnvironmentVariables['ProgramData'] = $programData }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $p = [System.Diagnostics.Process]::Start($psi)
        # Read both streams asynchronously so that neither pipe can fill up and block the test.
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        $finished = $p.WaitForExit($TimeoutMinutes * 60 * 1000)
        if (-not $finished) { try { $p.Kill() } catch { Write-Verbose "already exited: $_" } ; $p.WaitForExit() }
        $watch.Stop()
        $stdout = $outTask.Result
        $stderr = $errTask.Result

        $count = 0
        $m = [regex]::Match($stdout, '(\d+) tests ok')
        if ($m.Success) { $count = [int]$m.Groups[1].Value }
        $code = if ($finished) { $p.ExitCode } else { $null }
        $passed = $finished -and ($code -eq 0) -and $m.Success
        $note = if (-not $finished) { "timed out after $TimeoutMinutes min" } elseif (-not $m.Success) { "no 'tests ok' line" } else { '' }
        $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1)

        Write-Host "== $($folder.Name): exit $code, $count tests, $seconds s"
        if (-not $passed) {
            Write-Host '-- stdout'; Write-Host $stdout
            Write-Host '-- stderr'; Write-Host $stderr
            if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host "::error title=Unit test failed::$Label $($folder.Name): exit code $code $note" }
        }
        $results += [pscustomobject]@{ Binary = $folder.Name; ExitCode = $code; Tests = $count; Seconds = $seconds; Passed = $passed; Note = $note }
    }
} finally {
    if ($programData) { Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction SilentlyContinue }
}

$total = ($results | Measure-Object -Property Tests -Sum).Sum
$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$summary = "$Label`: $($results.Count) binaries, $total tests, $($failed.Count) failed"
Write-Host $summary

if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @("### Unit tests: $Label", '', '| Binary | Exit code | Tests | Seconds | Result |', '|---|---|---|---|---|')
    foreach ($r in $results) { $lines += "| $($r.Binary) | $($r.ExitCode) | $($r.Tests) | $($r.Seconds) | $(if ($r.Passed) { 'pass' } else { 'FAIL ' + $r.Note }) |" }
    $lines += '', "**$summary**", ''
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $lines -Encoding utf8
}

if ($failed.Count -gt 0) { exit 1 }
exit 0
