# Inspect CAB contents without running MSI actions or installing anything.
param([Parameter(Mandatory = $true)][string]$Msi,
      [Parameter(Mandatory = $true)][string]$ManagerDir,
      [Parameter(Mandatory = $true)][string]$Dark,
      [switch]$RequireSignatures)
$ErrorActionPreference = 'Stop'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('pn-msi-inspection-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    & $Dark -nologo -x (Join-Path $scratch 'payload') $Msi (Join-Path $scratch 'package.wxs')
    if ($LASTEXITCODE -ne 0) { throw "WiX dark failed to extract $Msi ($LASTEXITCODE)." }
    $payload = Join-Path $scratch 'payload/File'
    foreach ($file in 'OpenSSHServerPNManager.exe', 'OpenSSHServerPNManager.exe.config') {
        $packaged = Join-Path $payload $file
        if ((Get-FileHash $packaged -Algorithm SHA256).Hash -ne (Get-FileHash (Join-Path $ManagerDir $file) -Algorithm SHA256).Hash) {
            throw "MSI payload differs from the tested manager: $file"
        }
        Write-Host "PASS: MSI contains the exact tested $file."
    }
    if ($RequireSignatures) {
        $targets = @(Get-ChildItem $payload -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' } | ForEach-Object FullName)
        $required = 'libcrypto.dll','scp.exe','ssh-keygen.exe','ssh-agent.exe','OpenSSHServerPNManager.exe',
            'sftp-server.exe','ssh-shellhost.exe','sshd-auth.exe','sshd-session.exe','sshd.exe',
            'ssh.exe','sftp.exe','ssh-add.exe','ssh-keyscan.exe','ssh-sk-helper.exe','ssh-pkcs11-helper.exe'
        foreach ($name in $required) {
            if (-not (Test-Path -LiteralPath (Join-Path $payload $name) -PathType Leaf)) { throw "Missing intended signing target in MSI: $name" }
        }
        & (Join-Path $PSScriptRoot 'Test-Authenticode.ps1') -Path (@($Msi) + $targets)
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected extraction directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
