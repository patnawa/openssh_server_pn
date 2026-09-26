<#
.SYNOPSIS
    Authenticode-signs files with signtool.exe and a code-signing certificate in PFX form (optional
    signing path of .github/workflows/openssh.yml, SIGNING_METHOD = pfx).

.DESCRIPTION
    Reads the certificate from the environment, never from the command line:
      SIGNING_PFX_BASE64    the .pfx file, base64-encoded (repository or environment secret)
      SIGNING_PFX_PASSWORD  its password (secret)
      SIGNING_TIMESTAMP_URL RFC 3161 time-stamp server (optional; default http://timestamp.digicert.com)
      SIGNING_TRUSTED_ROOT_BASE64  the root certificate (.cer, base64) of a private CA (optional). It is
                            added to the machine's trusted roots first, so that signtool verify and the
                            workflow's signature check accept a certificate from that CA. Use it only
                            on a disposable machine such as a GitHub-hosted runner.
    The certificate is written to a file under RUNNER_TEMP (or TEMP) only for the signtool call and
    deleted afterwards. Each file is signed with SHA-256 and time-stamped, then checked with
    signtool verify /pa. A certificate on a hardware token or in a cloud HSM cannot be used this
    way; use SIGNING_METHOD = trusted-signing (Azure Artifact Signing) for that.

.PARAMETER Path
    Files to sign.

.PARAMETER Description
    Shown by Windows as the signed content's name (signtool /d).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Path,
    [string]$Description = 'OpenSSH Server PN',
    [string]$DescriptionUrl = 'https://github.com/patnawa/openssh_server_pn'
)
$ErrorActionPreference = 'Stop'

if (-not $env:SIGNING_PFX_BASE64 -or -not $env:SIGNING_PFX_PASSWORD) { throw 'SIGNING_PFX_BASE64 and SIGNING_PFX_PASSWORD must be set.' }
$timestamp = if ($env:SIGNING_TIMESTAMP_URL) { $env:SIGNING_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

# signtool from the newest Windows 10/11 SDK, host architecture x64 (it signs files of every architecture).
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signtool = Get-ChildItem -Path $kits -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found under $kits" }
Write-Host "signtool: $signtool"

$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
if ($env:SIGNING_TRUSTED_ROOT_BASE64) {
    $cer = Join-Path $tempRoot 'signing-root.cer'
    [IO.File]::WriteAllBytes($cer, [Convert]::FromBase64String($env:SIGNING_TRUSTED_ROOT_BASE64))
    $root = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
    Write-Host "Trusted root added for verification: $($root.Subject) ($($root.Thumbprint))"
    Remove-Item -LiteralPath $cer
}
$pfx = Join-Path $tempRoot ('signing-' + [guid]::NewGuid().ToString('N') + '.pfx')
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGNING_PFX_BASE64))
    foreach ($file in $Path) {
        $full = (Resolve-Path -LiteralPath $file).Path
        # The password goes to signtool as an argument (signtool has no other way); GitHub masks secrets in the log.
        & $signtool sign /fd SHA256 /td SHA256 /tr $timestamp /f $pfx /p $env:SIGNING_PFX_PASSWORD /d $Description /du $DescriptionUrl $full
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed for $full ($LASTEXITCODE)" }
        & $signtool verify /pa /q $full
        if ($LASTEXITCODE -ne 0) { throw "signtool verify failed for $full ($LASTEXITCODE)" }
        Write-Host "signed $full"
    }
} finally {
    Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
}
