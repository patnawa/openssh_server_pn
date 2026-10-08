param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$inventory = Get-Content (Join-Path $PSScriptRoot 'upstream-patches.json') -Raw | ConvertFrom-Json
if ($inventory.schemaVersion -ne 1) { throw 'Unsupported upstream patch inventory schema.' }
$manifest = Get-Content (Join-Path $RepoRoot 'src/contrib/win32/openssh/vcpkg.json') -Raw | ConvertFrom-Json
if ($inventory.upstream.vcpkgBaseline -ne $manifest.'builtin-baseline') { throw 'Update the upstream inventory for the changed vcpkg baseline.' }
$header = Get-Content (Join-Path $RepoRoot 'src/version.h') -Raw
$version = [regex]::Match($header, 'SSH_WINDOWS_VERSION\s+"OpenSSH_for_Windows_([0-9.]+)"').Groups[1].Value
$portable = [regex]::Match($header, 'SSH_PORTABLE\s+"(p[0-9]+)"').Groups[1].Value
if ($inventory.upstream.opensshPortable.tag -ne ('V_' + $version.Replace('.', '_') + '_' + $portable.ToUpperInvariant())) { throw 'OpenSSH changed: reconcile the inventory with the new upstream release.' }
foreach ($dependency in $manifest.overrides) {
    $record = @($inventory.upstream.libraries | Where-Object { $_.name -eq $dependency.name })
    if ($record.Count -ne 1 -or $record[0].version -ne $dependency.version) { throw "Update upstream inventory version for $($dependency.name)." }
    $overlay = Join-Path $RepoRoot ("src/contrib/win32/openssh/vcpkg_overlay_ports/$($dependency.name)/vcpkg.json")
    if ((Test-Path $overlay) -and (Get-Content $overlay -Raw | ConvertFrom-Json).version -ne $dependency.version) { throw "Overlay version disagrees with override: $($dependency.name)" }
    if (Test-Path $overlay) {
        $portfile = Get-Content (Join-Path (Split-Path $overlay -Parent) 'portfile.cmake') -Raw
        $archiveHash = [regex]::Match($portfile, 'SHA512\s+([a-f0-9]{128})').Groups[1].Value
        if ($record[0].sourceSha512 -ne $archiveHash) { throw "Update upstream archive identity for $($dependency.name)." }
    }
}
$seen = @{}
foreach ($patch in $inventory.overlayPatches) {
    if ($seen.ContainsKey($patch.path)) { throw "Duplicate inventory entry: $($patch.path)" }
    $seen[$patch.path] = $true
    $path = Join-Path $RepoRoot $patch.path
    $normalized = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($hash -ne $patch.sha256Lf) { throw "Patch changed; review rationale, removal condition and hash: $($patch.path)" }
    if (-not $patch.rationale -or -not $patch.removeWhen) { throw "Patch lacks maintenance instructions: $($patch.path)" }
    $portfile = Get-Content (Join-Path (Split-Path $path -Parent) 'portfile.cmake') -Raw
    if (-not $portfile.Contains((Split-Path $path -Leaf))) { throw "Inventory lists an unapplied patch: $($patch.path)" }
}
$overlayRoot = Join-Path $RepoRoot 'src/contrib/win32/openssh/vcpkg_overlay_ports'
foreach ($patch in Get-ChildItem $overlayRoot -Recurse -File | Where-Object { $_.Extension -in '.patch', '.diff' }) {
    $relative = $patch.FullName.Substring($RepoRoot.Length + 1).Replace('\', '/')
    if (-not $seen.ContainsKey($relative)) { throw "Undocumented local patch: $relative" }
}
foreach ($adjustment in $inventory.localSourceAdjustments) {
    foreach ($path in $adjustment.paths) { if (-not (Test-Path (Join-Path $RepoRoot $path))) { throw "Missing adapted source: $path" } }
    if (-not $adjustment.rationale -or -not $adjustment.removeWhen -or -not $adjustment.verification) { throw "Incomplete source adjustment: $($adjustment.id)" }
}
Write-Host "PASS: upstream versions, $($seen.Count) overlay patches, and $($inventory.localSourceAdjustments.Count) source adjustment records are consistent."
