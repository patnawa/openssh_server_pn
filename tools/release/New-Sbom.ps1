#Requires -Version 7.0
<#
.SYNOPSIS
    Writes a CycloneDX 1.5 JSON SBOM for a release of OpenSSH Server PN.

.DESCRIPTION
    Everything comes from the repository, nothing from the network:

    | Component            | Version from                                                                 |
    |----------------------|------------------------------------------------------------------------------|
    | OpenSSH Server PN    | FILEVERSION in src/contrib/win32/openssh/version.rc (or -Version)             |
    | OpenSSH              | SSH_WINDOWS_VERSION and SSH_PORTABLE in src/version.h (10.5 + p1 = 10.5p1)    |
    | LibreSSL, libfido2   | the overlay port manifests in src/contrib/win32/openssh/vcpkg_overlay_ports  |
    |                      | (overlay ports win over the registry, so that is the version that is built); |
    |                      | cross-checked against the overrides in vcpkg.json. Source archive SHA-512    |
    |                      | from the overlay portfile.                                                   |
    | libcbor, zlib        | the overrides in src/contrib/win32/openssh/vcpkg.json (vcpkg registry ports)  |

    Release files given with -File (the MSIs, OpenSSHServerManager.exe and its .exe.config) are
    listed as components of type "file" with their SHA-256 and SHA-512.

    The output is deterministic: the serial number is derived from the content, and the time stamp
    is SOURCE_DATE_EPOCH when set, otherwise the commit time of HEAD, otherwise the current time.
    The document is checked before it is written (required fields, unique bom-refs, dependency
    references, hash and purl formats); an invalid document is not written and the script fails.

    Pure PowerShell 7, no modules; runs on Windows, Linux and macOS.

.PARAMETER RepoRoot
    Repository root. Default: two folders above this script.

.PARAMETER Version
    Product version (e.g. 10.5.1.0). Default: FILEVERSION from version.rc.

.PARAMETER File
    Release files to list with hashes.

.PARAMETER OutFile
    Where to write the SBOM. Default: standard output.

.PARAMETER Repository
    GitHub owner/name of this project, for the purl and the links.

.EXAMPLE
    ./tools/release/New-Sbom.ps1 -File dist/*.msi, dist/OpenSSHServerManager.exe -OutFile dist/OpenSSH-Server-PN-v10.5.1.0.cdx.json
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..' '..'),
    [string]$Version = '',
    [string[]]$File = @(),
    [string]$OutFile = '',
    [string]$Repository = 'patnawa/openssh_server_pn'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$ScriptVersion = '1.0.0'

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$src = Join-Path $RepoRoot 'src'
$opensshDir = Join-Path $src 'contrib' 'win32' 'openssh'
$overlayDir = Join-Path $opensshDir 'vcpkg_overlay_ports'

function Read-Text([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing file: $Path" }
    Get-Content -LiteralPath $Path -Raw
}

function Get-Match([string]$Text, [string]$Pattern, [string]$What) {
    $m = [regex]::Match($Text, $Pattern)
    if (-not $m.Success) { throw "Cannot find $What (pattern $Pattern)" }
    $m
}

# ---------------------------------------------------------------- versions from the repository
$rc = Read-Text (Join-Path $opensshDir 'version.rc')
$fv = Get-Match $rc '(?m)^\s*FILEVERSION\s+(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)' 'FILEVERSION in version.rc'
$fileVersion = (1..4 | ForEach-Object { $fv.Groups[$_].Value }) -join '.'
if (-not $Version) { $Version = $fileVersion }
if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw "Version '$Version' is not of the form a.b.c.d" }

$versionH = Read-Text (Join-Path $src 'version.h')
$winVer = [regex]::Match($versionH, '#define\s+SSH_WINDOWS_VERSION\s+"OpenSSH_for_Windows_([0-9.]+)"')
if (-not $winVer.Success) { $winVer = Get-Match $versionH '#define\s+SSH_VERSION\s+"OpenSSH_([0-9.]+)"' 'SSH_VERSION in version.h' }
$portable = (Get-Match $versionH '#define\s+SSH_PORTABLE\s+"(p\d+)"' 'SSH_PORTABLE in version.h').Groups[1].Value
$opensshBase = $winVer.Groups[1].Value                      # 10.5
$opensshVersion = $opensshBase + $portable                  # 10.5p1
$opensshTag = 'V_' + ($opensshBase -replace '\.', '_') + '_' + $portable.ToUpperInvariant()   # V_10_5_P1

$manifest = Read-Text (Join-Path $opensshDir 'vcpkg.json') | ConvertFrom-Json
$overrides = @{}
foreach ($o in @($manifest.overrides)) { $overrides[$o.name] = $o.version }
$baseline = $manifest.'builtin-baseline'

function Get-LibraryVersion([string]$Name) {
    $overlayManifest = Join-Path $overlayDir $Name 'vcpkg.json'
    $override = $overrides[$Name]
    if (Test-Path -LiteralPath $overlayManifest) {
        $overlay = (Read-Text $overlayManifest | ConvertFrom-Json)
        $v = if ($overlay.PSObject.Properties['version']) { $overlay.version } elseif ($overlay.PSObject.Properties['version-string']) { $overlay.'version-string' } else { $null }
        if (-not $v) { throw "No version in $overlayManifest" }
        if ($override -and $override -ne $v) { Write-Warning "$Name`: overlay port $v, vcpkg.json override $override; the overlay port is what vcpkg builds." }
        return [pscustomobject]@{ Version = $v; Overlay = $true; Manifest = $overlay }
    }
    if (-not $override) { throw "No version for $Name in the overrides of vcpkg.json" }
    [pscustomobject]@{ Version = $override; Overlay = $false; Manifest = $null }
}

function Get-PortfileSource([string]$Name) {
    $portfile = Join-Path $overlayDir $Name 'portfile.cmake'
    if (-not (Test-Path -LiteralPath $portfile)) { return $null }
    $text = Read-Text $portfile
    $sha = [regex]::Match($text, 'SHA512\s+([0-9a-fA-F]{128})')
    if (-not $sha.Success) { return $null }
    [pscustomobject]@{ Text = $text; Sha512 = $sha.Groups[1].Value.ToLowerInvariant() }
}

$libressl = Get-LibraryVersion 'libressl'
$libfido2 = Get-LibraryVersion 'libfido2'
$libcbor = Get-LibraryVersion 'libcbor'
$zlib = Get-LibraryVersion 'zlib'

# ---------------------------------------------------------------- components
function New-Hash([string]$Path) {
    @(
        [ordered]@{ alg = 'SHA-256'; content = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
        [ordered]@{ alg = 'SHA-512'; content = (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash.ToLowerInvariant() }
    )
}

$repoUrl = "https://github.com/$Repository"
$repoPurl = 'pkg:github/' + $Repository.ToLowerInvariant()

$opensshComponent = [ordered]@{
    type               = 'application'
    'bom-ref'          = 'openssh'
    supplier           = [ordered]@{ name = 'The OpenBSD project (OpenSSH)'; url = @('https://www.openssh.com') }
    name               = 'OpenSSH'
    version            = $opensshVersion
    description        = "Portable OpenSSH $opensshVersion merged with the Windows port (PowerShell/openssh-portable) and changed by OpenSSH Server PN; Windows file version $fileVersion."
    scope              = 'required'
    licenses           = @([ordered]@{ license = [ordered]@{ id = 'SSH-OpenSSH'; url = 'https://github.com/openssh/openssh-portable/blob/master/LICENCE' } })
    cpe                = "cpe:2.3:a:openbsd:openssh:${opensshBase}:${portable}:*:*:*:*:*:*"
    purl               = "pkg:github/openssh/openssh-portable@$opensshTag"
    externalReferences = @(
        [ordered]@{ type = 'website'; url = 'https://www.openssh.com' }
        [ordered]@{ type = 'vcs'; url = 'https://github.com/openssh/openssh-portable' }
        [ordered]@{ type = 'release-notes'; url = "https://www.openssh.com/txt/release-$opensshBase" }
    )
    pedigree           = [ordered]@{
        ancestors = @(
            [ordered]@{
                type               = 'application'
                publisher          = 'Microsoft Corporation'
                name               = 'openssh-portable (Windows port)'
                purl               = 'pkg:github/powershell/openssh-portable'
                externalReferences = @([ordered]@{ type = 'vcs'; url = 'https://github.com/PowerShell/openssh-portable' })
            }
        )
        notes     = "The source in src/ of $repoUrl; the merges of OpenSSH releases and the Windows changes are listed in docs/CHANGELOG.md."
    }
    properties         = @([ordered]@{ name = 'openssh-server-pn:file-version'; value = $fileVersion })
}

$libresslSource = Get-PortfileSource 'libressl'
$libresslComponent = [ordered]@{
    type               = 'library'
    'bom-ref'          = 'libressl'
    supplier           = [ordered]@{ name = 'The OpenBSD project (LibreSSL)'; url = @('https://www.libressl.org') }
    name               = 'LibreSSL'
    version            = $libressl.Version
    description        = 'libcrypto only, built as libcrypto.dll by the vcpkg overlay port with the project''s patches (version resource, CMake changes).'
    scope              = 'required'
    # The vcpkg manifest says ISC; LibreSSL's COPYING keeps the OpenSSL and SSLeay terms for the code inherited from
    # OpenSSL (see NOTICE.txt in the package), so both are listed.
    licenses           = @([ordered]@{ expression = 'OpenSSL AND ISC' })
    cpe                = "cpe:2.3:a:openbsd:libressl:$($libressl.Version):*:*:*:*:*:*:*"
    purl               = "pkg:github/libressl/portable@v$($libressl.Version)"
    externalReferences = @(
        [ordered]@{ type = 'website'; url = 'https://www.libressl.org' }
        [ordered]@{ type = 'vcs'; url = 'https://github.com/libressl/portable' }
        [ordered]@{ type = 'release-notes'; url = "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$($libressl.Version)-relnotes.txt" }
    )
    properties         = @(
        [ordered]@{ name = 'openssh-server-pn:linkage'; value = 'dynamic (libcrypto.dll)' }
        [ordered]@{ name = 'openssh-server-pn:vcpkg-port'; value = 'overlay: src/contrib/win32/openssh/vcpkg_overlay_ports/libressl' }
    )
}
if ($libresslSource) {
    $libresslComponent.externalReferences += [ordered]@{
        type = 'distribution'; url = "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$($libressl.Version).tar.gz"
        comment = 'Source archive; SHA-512 as pinned in the overlay portfile'
        hashes = @([ordered]@{ alg = 'SHA-512'; content = $libresslSource.Sha512 })
    }
}

$fidoSource = Get-PortfileSource 'libfido2'
$libfido2Component = [ordered]@{
    type               = 'library'
    'bom-ref'          = 'libfido2'
    supplier           = [ordered]@{ name = 'Yubico AB'; url = @('https://developers.yubico.com/libfido2/') }
    name               = 'libfido2'
    version            = $libfido2.Version
    scope              = 'required'
    licenses           = @([ordered]@{ license = [ordered]@{ id = 'BSD-2-Clause' } })
    purl               = "pkg:github/yubico/libfido2@$($libfido2.Version)"
    externalReferences = @(
        [ordered]@{ type = 'website'; url = 'https://developers.yubico.com/libfido2/' }
        [ordered]@{ type = 'vcs'; url = 'https://github.com/Yubico/libfido2' }
        [ordered]@{ type = 'release-notes'; url = "https://github.com/Yubico/libfido2/releases/tag/$($libfido2.Version)" }
    )
    properties         = @(
        [ordered]@{ name = 'openssh-server-pn:linkage'; value = 'static' }
        [ordered]@{ name = 'openssh-server-pn:vcpkg-port'; value = 'overlay: src/contrib/win32/openssh/vcpkg_overlay_ports/libfido2' }
    )
}
if ($fidoSource) {
    $repoMatch = [regex]::Match($fidoSource.Text, 'REPO\s+(\S+)')
    $fidoRepo = if ($repoMatch.Success) { $repoMatch.Groups[1].Value } else { 'Yubico/libfido2' }
    $libfido2Component.externalReferences += [ordered]@{
        type = 'distribution'; url = "https://github.com/$fidoRepo/archive/$($libfido2.Version).tar.gz"
        comment = 'Source archive (vcpkg_from_github); SHA-512 as pinned in the overlay portfile'
        hashes = @([ordered]@{ alg = 'SHA-512'; content = $fidoSource.Sha512 })
    }
}

$libcborComponent = [ordered]@{
    type               = 'library'
    'bom-ref'          = 'libcbor'
    name               = 'libcbor'
    version            = $libcbor.Version
    scope              = 'required'
    licenses           = @([ordered]@{ license = [ordered]@{ id = 'MIT' } })
    purl               = "pkg:github/pjk/libcbor@v$($libcbor.Version)"
    externalReferences = @(
        [ordered]@{ type = 'vcs'; url = 'https://github.com/PJK/libcbor' }
        [ordered]@{ type = 'release-notes'; url = "https://github.com/PJK/libcbor/releases/tag/v$($libcbor.Version)" }
    )
    properties         = @(
        [ordered]@{ name = 'openssh-server-pn:linkage'; value = 'static' }
        [ordered]@{ name = 'openssh-server-pn:vcpkg-port'; value = "registry port at baseline $baseline, version override" }
    )
}

$zlibComponent = [ordered]@{
    type               = 'library'
    'bom-ref'          = 'zlib'
    supplier           = [ordered]@{ name = 'Jean-loup Gailly and Mark Adler'; url = @('https://zlib.net') }
    name               = 'zlib'
    version            = $zlib.Version
    scope              = 'required'
    licenses           = @([ordered]@{ license = [ordered]@{ id = 'Zlib' } })
    cpe                = "cpe:2.3:a:zlib:zlib:$($zlib.Version):*:*:*:*:*:*:*"
    purl               = "pkg:github/madler/zlib@v$($zlib.Version)"
    externalReferences = @(
        [ordered]@{ type = 'website'; url = 'https://zlib.net' }
        [ordered]@{ type = 'vcs'; url = 'https://github.com/madler/zlib' }
    )
    properties         = @(
        [ordered]@{ name = 'openssh-server-pn:linkage'; value = 'static' }
        [ordered]@{ name = 'openssh-server-pn:vcpkg-port'; value = "registry port at baseline $baseline, version override" }
    )
}

$components = [System.Collections.Generic.List[object]]::new()
foreach ($c in $opensshComponent, $libresslComponent, $libfido2Component, $libcborComponent, $zlibComponent) { $components.Add($c) }

# Release files
$fileRefs = @()
$resolvedFiles = @($File | Where-Object { $_ } | ForEach-Object { Resolve-Path -Path $_ } | ForEach-Object { $_.Path } | Sort-Object -Unique)
# The management console's version: from the executable itself (the committed binary is what is published; .NET
# reads the version resource on Windows and the assembly metadata elsewhere), else from the source.
$managerVersion = $null
$managerExe = $resolvedFiles | Where-Object { (Split-Path $_ -Leaf) -eq 'OpenSSHServerManager.exe' } | Select-Object -First 1
if ($managerExe) { $managerVersion = (Get-Item -LiteralPath $managerExe).VersionInfo.ProductVersion }
if (-not $managerVersion) {
    $programCs = Join-Path $RepoRoot 'tools' 'OpenSSH-Server-Manager' 'Program.cs'
    if (Test-Path -LiteralPath $programCs) {
        $mv = [regex]::Match((Read-Text $programCs), 'AppVersion\s*=\s*"([^"]+)"')
        if ($mv.Success) { $managerVersion = $mv.Groups[1].Value }
    }
}
foreach ($path in $resolvedFiles) {
    $item = Get-Item -LiteralPath $path
    $name = $item.Name
    $ref = "file:$name"
    $description = switch -Regex ($name) {
        'Win64' { 'Windows Installer package for x64' }
        'Win32' { 'Windows Installer package for x86' }
        'ARM64' { 'Windows Installer package for ARM64' }
        '^OpenSSHServerManager\.exe$' { 'OpenSSH Server Manager, the management console (.NET Framework 4.x, AnyCPU); the executable committed in tools/OpenSSH-Server-Manager/bin' }
        '\.exe\.config$' { 'Configuration file of OpenSSH Server Manager (keep it next to the executable)' }
        default { 'Release file' }
    }
    $fileVersionOf = if ($name -like '*.msi') { $Version } elseif ($name -like 'OpenSSHServerManager.exe*' -and $managerVersion) { $managerVersion } else { $null }
    $component = [ordered]@{ type = 'file'; 'bom-ref' = $ref; name = $name }
    if ($fileVersionOf) { $component.version = $fileVersionOf }
    $component.description = $description
    $component.hashes = New-Hash $path
    $component.properties = @([ordered]@{ name = 'openssh-server-pn:size'; value = [string]$item.Length })
    $components.Add($component)
    $fileRefs += $ref
}

$rootRef = 'openssh-server-pn'
$root = [ordered]@{
    type               = 'application'
    'bom-ref'          = $rootRef
    supplier           = [ordered]@{ name = 'OpenSSH Server PN'; url = @($repoUrl) }
    name               = 'OpenSSH Server PN'
    version            = $Version
    description        = 'OpenSSH server and client for Windows with installer (WiX MSI for x64, x86 and ARM64) and management console.'
    licenses           = @([ordered]@{ license = [ordered]@{ id = 'SSH-OpenSSH'; url = "$repoUrl/blob/main/src/LICENCE" } })
    purl               = "$repoPurl@v$Version"
    externalReferences = @(
        [ordered]@{ type = 'vcs'; url = $repoUrl }
        [ordered]@{ type = 'issue-tracker'; url = "$repoUrl/issues" }
        [ordered]@{ type = 'distribution'; url = "$repoUrl/releases/tag/v$Version" }
        [ordered]@{ type = 'release-notes'; url = "$repoUrl/blob/v$Version/docs/CHANGELOG.md" }
    )
}

# ---------------------------------------------------------------- dependencies
$known = @('libressl', 'libfido2', 'libcbor', 'zlib')
$fidoDeps = @('libcbor', 'libressl', 'zlib')
if ($libfido2.Manifest -and $libfido2.Manifest.PSObject.Properties['dependencies']) {
    $fidoDeps = @($libfido2.Manifest.dependencies | ForEach-Object { if ($_ -is [string]) { $_ } elseif (-not ($_.PSObject.Properties['host'] -and $_.host)) { $_.name } } | Where-Object { $_ -in $known } | Sort-Object -Unique)
}
$dependencies = @(
    [ordered]@{ ref = $rootRef; dependsOn = @(@('openssh') + $fileRefs) }
    [ordered]@{ ref = 'openssh'; dependsOn = @('libfido2', 'libressl', 'zlib') }
    [ordered]@{ ref = 'libfido2'; dependsOn = $fidoDeps }
    [ordered]@{ ref = 'libressl'; dependsOn = @() }
    [ordered]@{ ref = 'libcbor'; dependsOn = @() }
    [ordered]@{ ref = 'zlib'; dependsOn = @() }
)
foreach ($ref in $fileRefs) {
    $dependencies += [ordered]@{ ref = $ref; dependsOn = @(if ($ref -like '*.msi') { 'openssh' }) }
}

# ---------------------------------------------------------------- metadata, serial number, time stamp
$commit = $env:GITHUB_SHA
$epoch = $null
if ($env:SOURCE_DATE_EPOCH) { $epoch = [long]$env:SOURCE_DATE_EPOCH }
if (Get-Command git -ErrorAction SilentlyContinue) {
    if (-not $commit) { $c = & git -C $RepoRoot rev-parse HEAD 2>$null; if ($LASTEXITCODE -eq 0) { $commit = "$c".Trim() } }
    if ($null -eq $epoch) { $t = & git -C $RepoRoot log -1 --format=%ct 2>$null; if ($LASTEXITCODE -eq 0 -and "$t".Trim()) { $epoch = [long]"$t".Trim() } }
}
$timestamp = if ($null -ne $epoch) { [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime } else { [DateTime]::UtcNow }

$properties = @([ordered]@{ name = 'openssh-server-pn:vcpkg-builtin-baseline'; value = "$baseline" })
if ($commit) { $properties += [ordered]@{ name = 'openssh-server-pn:source-commit'; value = $commit } }

# Serial number: a name-based UUID (version 5 layout) over the content, so the same inputs give the same document.
$seedLines = @($Version, $commit, $baseline) + @($components | ForEach-Object {
    $h = if ($_.Contains('hashes')) { ($_.hashes | ForEach-Object { $_.content }) -join ',' } else { '' }
    "$($_.name)@$(if ($_.Contains('version')) { $_.version })#$h"
})
$sha1 = [Security.Cryptography.SHA1]::HashData([Text.Encoding]::UTF8.GetBytes(($seedLines -join "`n")))
$b = $sha1[0..15]
$b[6] = ($b[6] -band 0x0F) -bor 0x50
$b[8] = ($b[8] -band 0x3F) -bor 0x80
$hex = -join ($b | ForEach-Object { $_.ToString('x2') })
$serial = 'urn:uuid:{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = $serial
    version      = 1
    metadata     = [ordered]@{
        timestamp  = $timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        lifecycles = @([ordered]@{ phase = 'build' })
        tools      = [ordered]@{
            components = @([ordered]@{
                    type               = 'application'
                    name               = 'New-Sbom.ps1'
                    version            = $ScriptVersion
                    externalReferences = @([ordered]@{ type = 'vcs'; url = "$repoUrl/blob/main/tools/release/New-Sbom.ps1" })
                })
        }
        component  = $root
        properties = $properties
    }
    components   = $components.ToArray()
    dependencies = $dependencies
}

# ---------------------------------------------------------------- validation
function Test-CycloneDx([string]$Json) {
    $errors = [System.Collections.Generic.List[string]]::new()
    try { $d = $Json | ConvertFrom-Json -Depth 64 } catch { return @("not valid JSON: $($_.Exception.Message)") }
    $has = { param($o, $n) $null -ne $o -and $o.PSObject.Properties[$n] -and $null -ne $o.$n }
    if ($d.bomFormat -ne 'CycloneDX') { $errors.Add('bomFormat must be CycloneDX') }
    if ($d.specVersion -ne '1.5') { $errors.Add('specVersion must be 1.5') }
    if (-not (& $has $d 'serialNumber') -or $d.serialNumber -notmatch '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') { $errors.Add('serialNumber must be urn:uuid:<RFC 4122 UUID>') }
    if ($d.version -isnot [long] -and $d.version -isnot [int] -or $d.version -lt 1) { $errors.Add('version must be an integer >= 1') }
    if (-not (& $has $d 'metadata') -or -not (& $has $d.metadata 'component')) { $errors.Add('metadata.component is missing') }
    # Checked on the text: ConvertFrom-Json turns date strings into DateTime values.
    if ($Json -notmatch '"timestamp":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') { $errors.Add('metadata.timestamp must be an ISO 8601 UTC date-time') }

    $types = 'application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data'
    $hashAlgs = 'MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512', 'BLAKE3'
    $refTypes = 'vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation', 'support', 'distribution', 'distribution-intake', 'license', 'build-meta', 'build-system', 'release-notes', 'security-contact', 'model-card', 'log', 'configuration', 'evidence', 'formulation', 'attestation', 'threat-model', 'adversary-model', 'risk-assessment', 'vulnerability-assertion', 'exploitability-statement', 'pentest-report', 'static-analysis-report', 'dynamic-analysis-report', 'runtime-analysis-report', 'component-analysis-report', 'maturity-report', 'certification-report', 'codified-infrastructure', 'quality-metrics', 'poam', 'other'
    $refs = [System.Collections.Generic.HashSet[string]]::new()

    $checkHashes = {
        param($hashes, $where)
        foreach ($h in @($hashes)) {
            if ($h.alg -notin $hashAlgs) { $errors.Add("$where`: unknown hash algorithm '$($h.alg)'") }
            if ($h.content -notmatch '^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$') { $errors.Add("$where`: hash content is not hex of a valid length") }
        }
    }
    $checkComponent = $null
    $checkComponent = {
        param($c, $where)
        if (-not (& $has $c 'type') -or $c.type -notin $types) { $errors.Add("$where`: type missing or invalid ('$(if (& $has $c 'type') { $c.type })')") }
        if (-not (& $has $c 'name') -or [string]::IsNullOrWhiteSpace($c.name)) { $errors.Add("$where`: name missing") }
        if (& $has $c 'bom-ref') { if (-not $refs.Add($c.'bom-ref')) { $errors.Add("$where`: duplicate bom-ref '$($c.'bom-ref')'") } }
        if ((& $has $c 'purl') -and $c.purl -notmatch '^pkg:[a-z0-9.+-]+/') { $errors.Add("$where`: purl '$($c.purl)' is malformed") }
        if ((& $has $c 'cpe') -and $c.cpe -notmatch '^cpe:2\.3:[aho\*\-]') { $errors.Add("$where`: cpe '$($c.cpe)' is malformed") }
        if (& $has $c 'hashes') { & $checkHashes $c.hashes $where }
        if (& $has $c 'licenses') {
            $l = @($c.licenses)
            $exprs = @($l | Where-Object { $_.PSObject.Properties['expression'] })
            if ($exprs.Count -gt 0 -and $l.Count -ne 1) { $errors.Add("$where`: a license expression must be the only licenses entry") }
            foreach ($x in $l) {
                if ($x.PSObject.Properties['license']) {
                    $lic = $x.license
                    $hasId = $lic.PSObject.Properties['id'] -and $lic.id; $hasName = $lic.PSObject.Properties['name'] -and $lic.name
                    if ([int][bool]$hasId + [int][bool]$hasName -ne 1) { $errors.Add("$where`: a license needs exactly one of id or name") }
                } elseif (-not $x.PSObject.Properties['expression']) { $errors.Add("$where`: licenses entry is neither license nor expression") }
            }
        }
        if (& $has $c 'externalReferences') {
            foreach ($e in @($c.externalReferences)) {
                if ($e.type -notin $refTypes) { $errors.Add("$where`: unknown external reference type '$($e.type)'") }
                if ([string]::IsNullOrWhiteSpace($e.url)) { $errors.Add("$where`: external reference without url") }
                if ($e.PSObject.Properties['hashes']) { & $checkHashes $e.hashes "$where external reference" }
            }
        }
        if ((& $has $c 'pedigree') -and (& $has $c.pedigree 'ancestors')) {
            $i = 0; foreach ($a in @($c.pedigree.ancestors)) { & $checkComponent $a "$where pedigree ancestor $i"; $i++ }
        }
    }
    if (& $has $d 'metadata') {
        if (& $has $d.metadata 'component') { & $checkComponent $d.metadata.component 'metadata.component' }
        if ((& $has $d.metadata 'tools') -and (& $has $d.metadata.tools 'components')) { $i = 0; foreach ($t in @($d.metadata.tools.components)) { & $checkComponent $t "metadata.tools.components[$i]"; $i++ } }
    }
    $i = 0
    foreach ($c in @($d.components)) { & $checkComponent $c "components[$i] ($($c.name))"; $i++ }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($dep in @($d.dependencies)) {
        if (-not $refs.Contains($dep.ref)) { $errors.Add("dependencies: ref '$($dep.ref)' is not a bom-ref") }
        if (-not $seen.Add($dep.ref)) { $errors.Add("dependencies: ref '$($dep.ref)' listed twice") }
        foreach ($on in @($dep.dependsOn)) { if ($on -and -not $refs.Contains($on)) { $errors.Add("dependencies: '$($dep.ref)' depends on unknown ref '$on'") } }
    }
    $errors
}

$json = (ConvertTo-Json -InputObject $bom -Depth 32) -replace "`r`n", "`n"
$problems = @(Test-CycloneDx $json)
if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    throw "The generated SBOM is not valid ($($problems.Count) problem(s)); nothing written."
}

if ($OutFile) {
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($OutFile))
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutFile), $json + "`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $OutFile (CycloneDX 1.5; OpenSSH $opensshVersion, LibreSSL $($libressl.Version), libfido2 $($libfido2.Version), libcbor $($libcbor.Version), zlib $($zlib.Version); $($fileRefs.Count) file(s))"
} else {
    $json
}
