#Requires -Version 7.0
<#
.SYNOPSIS
    Compares the upstream versions of OpenSSH and the vendored libraries with the ones in this repository.

.DESCRIPTION
    | Component      | In this repository                                   | Latest upstream                                              |
    |----------------|------------------------------------------------------|--------------------------------------------------------------|
    | OpenSSH        | src/version.h (SSH_WINDOWS_VERSION + SSH_PORTABLE)   | release tags V_x_y_Pz of openssh/openssh-portable            |
    | LibreSSL       | overlay port manifest (vcpkg_overlay_ports/libressl) | tarballs on ftp.openbsd.org/pub/OpenBSD/LibreSSL (the URL    |
    |                |                                                      | the portfile downloads from); libressl/portable tags if the  |
    |                |                                                      | listing cannot be read                                       |
    | libfido2       | overlay port manifest (vcpkg_overlay_ports/libfido2) | release tags x.y.z of Yubico/libfido2                        |
    | libcbor        | overrides in src/contrib/win32/openssh/vcpkg.json    | release tags vx.y.z of PJK/libcbor                           |
    | zlib           | overrides in src/contrib/win32/openssh/vcpkg.json    | release tags vx.y.z of madler/zlib                           |
    | Win32-OpenSSH  | (informational only)                                 | newest release of PowerShell/Win32-OpenSSH                   |

    Tags are read with "git ls-remote", so no GitHub API token or rate limit is involved. Every
    component is checked on its own: a source that cannot be reached gives an Error for that row and
    the others are still reported.

    Output: one object per component (Component, Current, Latest, UpdateAvailable, Tag, ReleaseNotes,
    Source, Note, Error). -AsJson writes the same as JSON. The exit code is 0, also when updates are
    available; -FailOnError makes it 1 when a source could not be read.

    LibreSSL publishes development releases (typically x.y.0) next to stable ones; a newer version
    is reported either way, and the note says to check its release notes.

.PARAMETER RepoRoot
    Repository root. Default: two folders above this script.

.PARAMETER AsJson
    Write JSON instead of objects.

.PARAMETER OutFile
    Also write the JSON to this file.

.PARAMETER FailOnError
    Exit with 1 when an upstream source could not be read.

.EXAMPLE
    ./tools/release/Get-UpstreamVersions.ps1 | Format-Table Component, Current, Latest, UpdateAvailable
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..' '..'),
    [switch]$AsJson,
    [string]$OutFile = '',
    [switch]$FailOnError
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$opensshDir = Join-Path $RepoRoot 'src' 'contrib' 'win32' 'openssh'

function Get-RemoteTags([string]$Url) {
    <# Tag names of a git repository (without ^{} peel lines). #>
    $lines = & git ls-remote --tags --refs $Url 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git ls-remote $Url failed: $($lines -join ' ')" }
    @($lines | ForEach-Object { if ("$_" -match 'refs/tags/(.+)$') { $Matches[1] } })
}

function Select-Newest([object[]]$Items) {
    <# Items with a [version] Key; returns the one with the highest key. #>
    @($Items | Sort-Object -Property Key -Descending) | Select-Object -First 1
}

function Get-OverlayOrOverrideVersion([string]$Name) {
    $overlay = Join-Path $opensshDir 'vcpkg_overlay_ports' $Name 'vcpkg.json'
    if (Test-Path -LiteralPath $overlay) {
        $m = Get-Content -LiteralPath $overlay -Raw | ConvertFrom-Json
        if ($m.PSObject.Properties['version']) { return $m.version }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $opensshDir 'vcpkg.json') -Raw | ConvertFrom-Json
    $o = @($manifest.overrides) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if ($o) { return $o.version }
    throw "No version for $Name in the overlay ports or the overrides of vcpkg.json"
}

function New-Row([string]$Component, [string]$Current, [scriptblock]$Lookup) {
    $row = [ordered]@{ Component = $Component; Current = $Current; Latest = $null; UpdateAvailable = $null; Tag = $null; ReleaseNotes = $null; Source = $null; Note = $null; Error = $null }
    try {
        $r = & $Lookup
        foreach ($k in 'Latest', 'Tag', 'ReleaseNotes', 'Source', 'Note') { if ($r.Contains($k)) { $row[$k] = $r[$k] } }
        if ($r.Contains('Newer')) { $row.UpdateAvailable = [bool]$r.Newer }
    } catch {
        $row.Error = $_.Exception.Message
    }
    [pscustomobject]$row
}

$rows = @()

# ------------------------------------------------------------------ OpenSSH
$versionH = Get-Content -LiteralPath (Join-Path $RepoRoot 'src' 'version.h') -Raw
$base = [regex]::Match($versionH, '#define\s+SSH_WINDOWS_VERSION\s+"OpenSSH_for_Windows_([0-9.]+)"')
if (-not $base.Success) { $base = [regex]::Match($versionH, '#define\s+SSH_VERSION\s+"OpenSSH_([0-9.]+)"') }
$portable = [regex]::Match($versionH, '#define\s+SSH_PORTABLE\s+"p(\d+)"')
if (-not $base.Success -or -not $portable.Success) { throw 'Cannot read the OpenSSH version from src/version.h' }
$opensshCurrent = $base.Groups[1].Value + 'p' + $portable.Groups[1].Value
$opensshKey = [version]($base.Groups[1].Value + '.' + $portable.Groups[1].Value)
$rows += New-Row 'OpenSSH' $opensshCurrent {
    $tags = Get-RemoteTags 'https://github.com/openssh/openssh-portable.git'
    $items = foreach ($t in $tags) { if ($t -match '^V_(\d+)_(\d+)_P(\d+)$') { [pscustomobject]@{ Key = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"; Tag = $t; Text = "$($Matches[1]).$($Matches[2])p$($Matches[3])"; Base = "$($Matches[1]).$($Matches[2])" } } }
    $n = Select-Newest $items
    if (-not $n) { throw 'no V_x_y_Pz tags found' }
    [ordered]@{ Latest = $n.Text; Tag = $n.Tag; Newer = ($n.Key -gt $opensshKey); ReleaseNotes = "https://www.openssh.com/txt/release-$($n.Base)"; Source = 'git tags of github.com/openssh/openssh-portable'; Note = 'Merge with git subtree in the history clone (docs/BUILDING.md, section 2).' }
}

# ------------------------------------------------------------------ LibreSSL
$libresslCurrent = Get-OverlayOrOverrideVersion 'libressl'
$rows += New-Row 'LibreSSL' $libresslCurrent {
    $note = 'LibreSSL also publishes development releases; check the release notes before updating (Update-VcpkgPort.ps1, docs/BUILDING.md section 6).'
    try {
        $listing = (Invoke-WebRequest -Uri 'https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/' -UseBasicParsing -TimeoutSec 60).Content
        $versions = @([regex]::Matches($listing, 'libressl-(\d+\.\d+\.\d+)\.tar\.gz') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        if ($versions.Count -eq 0) { throw 'no tarballs in the listing' }
        $source = 'ftp.openbsd.org/pub/OpenBSD/LibreSSL'
    } catch {
        $versions = @(Get-RemoteTags 'https://github.com/libressl/portable.git' | ForEach-Object { if ($_ -match '^v(\d+\.\d+\.\d+)$') { $Matches[1] } })
        if ($versions.Count -eq 0) { throw "no versions found (listing: $($_.Exception.Message))" }
        $source = 'git tags of github.com/libressl/portable (the ftp listing could not be read)'
    }
    $n = Select-Newest @($versions | ForEach-Object { [pscustomobject]@{ Key = [version]$_; Text = $_ } })
    [ordered]@{ Latest = $n.Text; Tag = "v$($n.Text)"; Newer = ($n.Key -gt [version]$libresslCurrent); ReleaseNotes = "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$($n.Text)-relnotes.txt"; Source = $source; Note = $note }
}

# ------------------------------------------------------------------ libfido2, libcbor, zlib
$libraries = @(
    @{ Name = 'libfido2'; Url = 'https://github.com/Yubico/libfido2.git'; Pattern = '^(\d+\.\d+\.\d+)$'; Prefix = ''; Notes = 'https://github.com/Yubico/libfido2/releases/tag/{0}'; Note = 'Overlay port: Update-VcpkgPort.ps1 -Port libfido2 (docs/BUILDING.md section 6).' }
    @{ Name = 'libcbor'; Url = 'https://github.com/PJK/libcbor.git'; Pattern = '^v(\d+\.\d+\.\d+)$'; Prefix = 'v'; Notes = 'https://github.com/PJK/libcbor/releases/tag/v{0}'; Note = 'Registry port: the version must exist in the vcpkg registry; move builtin-baseline and the override in vcpkg.json.' }
    @{ Name = 'zlib'; Url = 'https://github.com/madler/zlib.git'; Pattern = '^v(\d+\.\d+(?:\.\d+)*)$'; Prefix = 'v'; Notes = 'https://github.com/madler/zlib/releases/tag/v{0}'; Note = 'Registry port: the version must exist in the vcpkg registry; move builtin-baseline and the override in vcpkg.json.' }
)
foreach ($lib in $libraries) {
    $current = Get-OverlayOrOverrideVersion $lib.Name
    $rows += New-Row $lib.Name $current {
        $items = foreach ($t in Get-RemoteTags $lib.Url) { if ($t -match $lib.Pattern) { [pscustomobject]@{ Key = [version]$Matches[1]; Text = $Matches[1] } } }
        $n = Select-Newest $items
        if (-not $n) { throw "no release tags found in $($lib.Url)" }
        [ordered]@{ Latest = $n.Text; Tag = $lib.Prefix + $n.Text; Newer = ($n.Key -gt [version]$current); ReleaseNotes = ($lib.Notes -f $n.Text); Source = "git tags of $($lib.Url -replace '^https://|\.git$', '')"; Note = $lib.Note }
    }
}

# ------------------------------------------------------------------ Win32-OpenSSH (informational)
$rows += New-Row 'Win32-OpenSSH' 'n/a' {
    # Release tags look like v9.8.3.0p2-Preview or 10.0.0.0p2-Preview.
    $items = foreach ($t in Get-RemoteTags 'https://github.com/PowerShell/Win32-OpenSSH.git') { if ($t -match '^v?(\d+\.\d+\.\d+\.\d+)p(\d+)') { [pscustomobject]@{ Key = [version]$Matches[1]; Text = $t } } }
    $n = Select-Newest $items
    if (-not $n) { throw 'no release tags found' }
    [ordered]@{ Latest = $n.Text; Tag = $n.Text; ReleaseNotes = "https://github.com/PowerShell/Win32-OpenSSH/releases/tag/$($n.Text)"; Source = 'git tags of github.com/PowerShell/Win32-OpenSSH'; Note = 'Informational: Microsoft''s Windows port. Its fixes to Windows-specific code have to be merged by hand; not compared automatically.' }
}

$json = ConvertTo-Json -InputObject @($rows) -Depth 4
if ($OutFile) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutFile), ($json -replace "`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false)) }
if ($AsJson) { $json } else { $rows }

if ($FailOnError -and @($rows | Where-Object { $_.Error }).Count -gt 0) { exit 1 }
