param([Parameter(Mandatory = $true)][string[]]$Path)
$ErrorActionPreference = 'Stop'
if ($Path.Count -eq 0) { throw 'No files supplied for Authenticode verification.' }
foreach ($file in $Path) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing signing target: $file" }
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate) {
        throw "Signature verification failed: $file ($($signature.Status)); a trusted signature and timestamp are required."
    }
    if ($env:SIGNING_CERTIFICATE_THUMBPRINT -and $signature.SignerCertificate.Thumbprint -ne $env:SIGNING_CERTIFICATE_THUMBPRINT) {
        throw "Unexpected signing certificate: $file"
    }
    Write-Host "Verified signature and timestamp: $file ($($signature.SignerCertificate.Subject))"
}
