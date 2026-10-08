<#
.SYNOPSIS
    Builds OpenSSHServerPNManager.exe from the C# source files in this folder.

.DESCRIPTION
    Restores hash-verified pinned Roslyn and .NET Framework 4.5 reference packages (or the compiler given with
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
    # Local overrides bypass the pinned inputs and are recorded as such in build-info.json.
    [string]$Csc,
    [string]$ReferenceDir
)
$ErrorActionPreference = 'Stop'

if ($Csc -and -not (Test-Path -LiteralPath $Csc)) { throw "No compiler at $Csc" }
$toolchain = Join-Path ([IO.Path]::GetTempPath()) ('openssh-toolchain-' + [guid]::NewGuid().ToString('N'))
try {
    if (-not $Csc -or -not $ReferenceDir) {
        $restored = & (Join-Path $PSScriptRoot 'Restore-Toolchain.ps1') -Destination $toolchain
    }
    $compiler = if ($Csc) { (Resolve-Path -LiteralPath $Csc).Path } else { $restored['microsoft.net.compilers.toolset'] }
    $fw = if ($ReferenceDir) { (Resolve-Path -LiteralPath $ReferenceDir).Path } else { $restored['microsoft.netframework.referenceassemblies.net45'] }
$sourceFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter *.cs | Sort-Object Name)
if ($sourceFiles.Count -eq 0) { throw "No .cs files in $PSScriptRoot" }
# Git checkout newline/BOM choices otherwise affect Roslyn's deterministic input hashes,
# manifest bytes, and physical newlines inside multiline test-helper literals. Compile a
# canonical UTF-8/LF copy, leaving the checkout untouched. Explicit \r/\n escapes are unchanged.
$normalizedRoot = Join-Path $toolchain 'normalized-source'
New-Item -ItemType Directory -Force -Path $normalizedRoot | Out-Null
$encoding = New-Object Text.UTF8Encoding $false
$src = @()
$inputHashes = @()
foreach ($file in @($sourceFiles) + @(Get-Item (Join-Path $PSScriptRoot 'app.manifest'))) {
    $normalized = Join-Path $normalizedRoot $file.Name
    $content = [IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n").Replace("`r","`n")
    [IO.File]::WriteAllText($normalized,$content,$encoding)
    $inputHashes += [ordered]@{ name = $file.Name; sha256 = (Get-FileHash $normalized -Algorithm SHA256).Hash.ToLowerInvariant() }
    if ($file.Extension -eq '.cs') { $src += $normalized }
}
$manifest = Join-Path $normalizedRoot 'app.manifest'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir 'OpenSSHServerPNManager.exe'

$refs = 'mscorlib.dll','System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.ServiceProcess.dll','System.Security.dll','Microsoft.CSharp.dll' |
    ForEach-Object { '/r:' + (Join-Path $fw $_) }

$cscArgs = @('/nologo', '/noconfig', '/nostdlib+', '/target:winexe', '/platform:anycpu', '/optimize+', '/warn:3', '/nowarn:1591', '/warnaserror+',
          "/out:$out", "/win32manifest:$manifest") + $refs
# The same source and compiler give the same bytes, so a published hash can be rebuilt and checked.
$cscArgs += @('/deterministic+', "/pathmap:$normalizedRoot=.")
# The program icon (icon\app.ico, made by icon\render.py): the executable's icon in Explorer and on the taskbar (/win32icon), and a resource
# the window loads with all its sizes, so the title bar gets the hand-made 16-24 px images (/resource).
$originalIcon = Join-Path $PSScriptRoot 'icon\app.ico'
if (Test-Path $originalIcon) {
    $icon = Join-Path $normalizedRoot 'icon/app.ico'
    New-Item -ItemType Directory -Path (Split-Path $icon -Parent) | Out-Null
    Copy-Item -LiteralPath $originalIcon -Destination $icon
    $inputHashes += [ordered]@{ name = 'icon/app.ico'; sha256 = (Get-FileHash $icon -Algorithm SHA256).Hash.ToLowerInvariant() }
    $cscArgs += @("/win32icon:$icon", "/resource:$icon,OpenSSHServerPNManager.app.ico")
}
else { Write-Warning "icon\app.ico not found: building without the program icon." }
$cscArgs += $src

Write-Host "Compiler: $compiler"
& $compiler @cscArgs
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

# Metadata accompanies the exact bytes that tests and release signing consume.
$metadata = [ordered]@{
    compilerVersion = ((& $compiler -version) -join ' ').Trim()
    pinnedToolchain = (-not $Csc -and -not $ReferenceDir)
    sourceNormalization = 'UTF-8 without BOM; LF physical newlines; normalized source root mapped to .; binary icon unchanged'
    inputs = $inputHashes
    toolchain = (Get-Content (Join-Path $PSScriptRoot 'build-toolchain.json') -Raw | ConvertFrom-Json)
    files = @('OpenSSHServerPNManager.exe','OpenSSHServerPNManager.exe.config' | ForEach-Object {
        [ordered]@{ name = $_; sha256 = (Get-FileHash (Join-Path $OutDir $_) -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}
[IO.File]::WriteAllText((Join-Path $OutDir 'build-info.json'), ($metadata | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
} finally {
    $resolved = [IO.Path]::GetFullPath($toolchain)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected toolchain directory: $resolved" }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
