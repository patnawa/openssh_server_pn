# Pinned inputs are verified on every use. Only archives are cached; each build extracts a
# fresh copy, so a changed extracted compiler/reference assembly cannot influence a build.
param([Parameter(Mandatory = $true)][string]$Destination,
      [string]$Cache = (Join-Path $env:LOCALAPPDATA 'OpenSSHServerPNBuild'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$lock = Get-Content (Join-Path $PSScriptRoot 'build-toolchain.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $Cache, $Destination | Out-Null
$paths = @{}
foreach ($package in $lock.packages) {
    $name = $package.id + '.' + $package.version + '.nupkg'
    $archive = Join-Path $Cache $name
    if (-not (Test-Path -LiteralPath $archive)) {
        $download = Join-Path $Cache ([guid]::NewGuid().ToString('N') + '.download')
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri ('https://api.nuget.org/v3-flatcontainer/' + $package.id + '/' + $package.version + '/' + $name) -OutFile $download
            if ((Get-FileHash $download -Algorithm SHA256).Hash -ne $package.sha256) { throw "Package hash mismatch: $name" }
            Move-Item -LiteralPath $download -Destination $archive -Force
        } finally { if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force } }
    }
    if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $package.sha256) { throw "Cached package hash mismatch: $archive. Remove this archive and retry." }
    $expanded = Join-Path $Destination $package.id
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $expanded)
    $paths[$package.id] = Join-Path $expanded $package.path
}
$paths
