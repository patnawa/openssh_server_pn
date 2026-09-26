<#
.SYNOPSIS
    Builds OpenSSHServerManager.exe from the C# source files in this folder.

.DESCRIPTION
    Uses the Roslyn C# compiler shipped with Visual Studio 2022 Build Tools (or the one given with
    -Csc). Targets .NET Framework 4.x so the result runs on Windows 7 SP1 / Server 2008 R2 and later
    without extra runtimes. Warnings stop the build.

.PARAMETER OutDir
    Folder for the compiled executable. Default: .\bin next to this script.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -OutDir C:\Users\me\Downloads
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot 'bin'),
    # A Roslyn csc.exe to use instead of the one of Visual Studio Build Tools (for example from the
    # Microsoft.Net.Compilers.Toolset package, to build with a pinned compiler version).
    [string]$Csc
)
$ErrorActionPreference = 'Stop'

$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path $fw)) { $fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
if (-not (Test-Path $fw)) { throw ".NET Framework 4.x runtime folder not found." }

$csc = $null
if ($Csc) { if (-not (Test-Path $Csc)) { throw "No compiler at $Csc" }; $csc = (Resolve-Path $Csc).Path }
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not $csc -and (Test-Path $vswhere)) {
    $vs = & $vswhere -products * -latest -property installationPath 2>$null
    if ($vs) {
        $cand = Join-Path $vs 'MSBuild\Current\Bin\Roslyn\csc.exe'
        if (Test-Path $cand) { $csc = $cand }
    }
}
# The inbox .NET Framework compiler (C# 5) cannot build this source: it uses C# 6 (exception filters, among others).
if (-not $csc) {
    throw "The Roslyn C# compiler was not found. Install Visual Studio 2022 Build Tools (see docs/BUILDING.md, section 1), or pass its csc.exe with -Csc."
}

$src = @(Get-ChildItem -Path $PSScriptRoot -Filter *.cs | Sort-Object Name | ForEach-Object FullName)
if ($src.Count -eq 0) { throw "No .cs files in $PSScriptRoot" }
$manifest = Join-Path $PSScriptRoot 'app.manifest'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir 'OpenSSHServerManager.exe'

$refs = 'mscorlib.dll','System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.ServiceProcess.dll','Microsoft.CSharp.dll' |
    ForEach-Object { '/r:' + (Join-Path $fw $_) }

$cscArgs = @('/nologo', '/noconfig', '/nostdlib+', '/target:winexe', '/platform:anycpu', '/optimize+', '/warn:3', '/nowarn:1591', '/warnaserror+',
          "/out:$out", "/win32manifest:$manifest") + $refs
# The same source and compiler give the same bytes, so a published hash can be rebuilt and checked.
$cscArgs += @('/deterministic+', "/pathmap:$PSScriptRoot=.")
# The program icon (icon\app.ico, made by icon\render.py): the executable's icon in Explorer and on the taskbar (/win32icon), and a resource
# the window loads with all its sizes, so the title bar gets the hand-made 16-24 px images (/resource).
$icon = Join-Path $PSScriptRoot 'icon\app.ico'
if (Test-Path $icon) { $cscArgs += @("/win32icon:$icon", "/resource:$icon,OpenSSHServerManager.app.ico") }
else { Write-Warning "icon\app.ico not found: building without the program icon." }
$cscArgs += $src

Write-Host "Compiler: $csc"
& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw "Compilation failed with exit code $LASTEXITCODE" }

# Run on any 4.x runtime; enable the newest runtime version installed. Written byte for byte the same everywhere
# (CRLF, UTF-8 without BOM), whatever the line endings of this script and whichever PowerShell runs it: the file is
# published with a SHA-256.
$config = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup useLegacyV2RuntimeActivationPolicy="false">
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5" />
  </startup>
  <runtime>
    <AppContextSwitchOverrides value="Switch.System.Windows.Forms.DoNotSupportSelectAllShortcutInMultilineTextBox=false" />
  </runtime>
</configuration>
"@
[IO.File]::WriteAllText("$out.config", (($config -replace "`r?`n", "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $false))

$fi = Get-Item $out
Write-Host "Built $($fi.FullName) ($($fi.Length) bytes)"
Write-Host "SHA256 $((Get-FileHash $out -Algorithm SHA256).Hash)"
