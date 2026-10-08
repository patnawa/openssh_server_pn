# A Windows PowerShell child launched with Start-Process inherits PowerShell 7's
# PSModulePath unchanged. Prefer its own modules before any inherited versions.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'This bootstrap requires Windows PowerShell 5.1.' }
$moduleRoot = Join-Path $PSHOME 'Modules'
$env:PSModulePath = (@($moduleRoot) + @($env:PSModulePath -split ';' | Where-Object { $_ -and $_ -ne $moduleRoot })) -join ';'
