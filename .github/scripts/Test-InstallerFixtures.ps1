# Non-elevated checks for the hosted installer-test harness. No MSI, service,
# firewall, scheduled task, or installed manager is changed by this script.
# Run with pwsh, matching the GitHub Actions parent of the Windows PowerShell child.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core') { throw 'Run these cross-edition fixture checks with PowerShell 7.' }
Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force
$passed = 0
function Assert-Fixture([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:passed++
    Write-Host "PASS: $Name"
}

# Minimal replay of the hosted MSI log: INSTALL ends while the asynchronous
# wizard is still running. Its actual opened/owner/request checks are separate.
$start = 'Action start 6:43:08: OpenSSHOpenWizard.'
$end = 'Action ended 6:43:08: OpenSSHOpenWizard. Return value '
$captured = $start + "`nAction ended 6:43:08: INSTALL. Return value 1.`n" + $end + '0.'
Assert-Fixture (Get-AsyncWizardLaunchEvidence $captured).Valid 'captured asynchronous wizard log is accepted'
Assert-Fixture (Get-AsyncWizardLaunchEvidence ($start+"`n"+$end+'1.')).Valid 'completed wizard action log is accepted'
Assert-Fixture (-not (Get-AsyncWizardLaunchEvidence '').Valid) 'missing wizard action is rejected'
Assert-Fixture (-not (Get-AsyncWizardLaunchEvidence ($end+'0.')).Valid) 'an end record without a launch start is rejected'
Assert-Fixture (-not (Get-AsyncWizardLaunchEvidence $start).Valid) 'an incomplete action record is rejected'
foreach ($code in '2','3','4','-1') {
    Assert-Fixture (-not (Get-AsyncWizardLaunchEvidence ($start+"`n"+$end+$code+'.')).Valid) "explicit action result $code is rejected"
}
Assert-Fixture (-not (Get-AsyncWizardLaunchEvidence ($captured+"`n"+$end+'3.')).Valid) 'a later failure cannot be hidden by an earlier non-failing result'

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('pn-installer-fixtures-' + [guid]::NewGuid().ToString('N'))
$originalModulePath = $env:PSModulePath
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $fixture = Join-Path $scratch 'hash-input.txt'
    [IO.File]::WriteAllText($fixture, 'fixture', [Text.UTF8Encoding]::new($false))
    $expectedHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
    $bootstrap = (Resolve-Path (Join-Path $PSScriptRoot 'Initialize-WindowsPowerShell.ps1')).Path
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $windowsModules = Join-Path (Split-Path $windowsPowerShell -Parent) 'Modules'
    # Start-Process, unlike PowerShell's native invocation adapter, preserves this
    # inherited Core-first search order. That is the original hosted failure.
    $env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + $windowsModules
    $probe = Join-Path $scratch 'child.ps1'
    [IO.File]::WriteAllText($probe, @'
param([string]$Bootstrap, [string]$Fixture, [switch]$Initialize)
$ErrorActionPreference = 'Stop'
if ($Initialize) { & $Bootstrap }
$hash = (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash
foreach ($name in 'Get-FileHash','Get-CimInstance','Get-NetTCPConnection','Export-ScheduledTask') {
    $null = Get-Command $name -ErrorAction Stop
}
'FILEHASH=' + $hash
'MODULE=' + (Get-Command Get-FileHash).Module.Path
'@, [Text.UTF8Encoding]::new($false))
    foreach ($initialize in $false,$true) {
        $suffix = if ($initialize) { 'fixed' } else { 'original' }
        $output = Join-Path $scratch ($suffix+'.out')
        $errorFile = Join-Path $scratch ($suffix+'.err')
        $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$probe+'"'),'-Bootstrap',('"'+$bootstrap+'"'),'-Fixture',('"'+$fixture+'"'))
        if ($initialize) { $arguments += '-Initialize' }
        $child = Start-Process $windowsPowerShell -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $output -RedirectStandardError $errorFile
        if (-not $child.WaitForExit(30000)) { $child.Kill(); throw 'Fixture child timed out.' }
        $stdout = [IO.File]::ReadAllText($output)
        $stderr = [IO.File]::ReadAllText($errorFile)
        if (-not $initialize) {
            Assert-Fixture ($child.ExitCode -ne 0 -and $stderr.Contains('Get-FileHash') -and $stderr.Contains('CommandNotFoundException')) 'original child reproduces the hosted Get-FileHash discovery failure'
        } else {
            Assert-Fixture ($child.ExitCode -eq 0 -and $stdout.Contains('FILEHASH='+$expectedHash)) 'bootstrapped child hashes the fixture and resolves all recovery cmdlets'
            $actualModule = @($stdout -split '\r?\n' | Where-Object { $_ -like 'MODULE=*' })[0].Substring('MODULE='.Length)
            $expectedModule = Join-Path $windowsModules 'Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1'
            Assert-Fixture ([string]::Equals([IO.Path]::GetFullPath($actualModule), [IO.Path]::GetFullPath($expectedModule), [StringComparison]::OrdinalIgnoreCase)) 'child loads its Windows PowerShell utility module'
        }
    }
} finally {
    $env:PSModulePath = $originalModulePath
    $resolved = [IO.Path]::GetFullPath($scratch)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected fixture directory: $resolved" }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
Write-Host "RESULT: $passed installer fixture checks passed."
