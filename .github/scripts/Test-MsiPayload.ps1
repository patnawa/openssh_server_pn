# Inspect CAB contents without running MSI actions or installing anything.
param([Parameter(Mandatory = $true)][string]$Msi,
      [Parameter(Mandatory = $true)][string]$ManagerDir,
      [Parameter(Mandatory = $true)][string]$Dark,
      [switch]$RequireSignatures)
$ErrorActionPreference = 'Stop'

# dark -x names an extracted file by its key in the File table, not by its installed name: WiX derives
# the key from the name (ssh-keygen.exe becomes ssh_keygen.exe) unless the source sets an Id. Installed
# name -> keys, from the package opened read-only.
function Get-MsiFileKeys([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `File`, `FileName` FROM `File`'))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $keys = @{}
    while ($true) {
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if (-not $record) { break }
        $key = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
        $name = ($record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(2)) -split '\|')[-1]   # short|long
        if ($keys.ContainsKey($name)) { $keys[$name] += $key } else { $keys[$name] = @($key) }
    }
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    foreach ($o in $view, $db, $installer) { [Runtime.InteropServices.Marshal]::ReleaseComObject($o) | Out-Null }
    $keys
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('pn-msi-inspection-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    & $Dark -nologo -x (Join-Path $scratch 'payload') $Msi (Join-Path $scratch 'package.wxs')
    if ($LASTEXITCODE -ne 0) { throw "WiX dark failed to extract $Msi ($LASTEXITCODE)." }
    $payload = Join-Path $scratch 'payload/File'
    $fileKeys = Get-MsiFileKeys $Msi
    # The extracted copies of an installed file; throws when the File table or the extraction lacks it.
    function Get-PayloadFile([string]$Name) {
        if (-not $fileKeys.ContainsKey($Name)) { throw "Not in the File table of the MSI: $Name" }
        foreach ($key in $fileKeys[$Name]) {
            $path = Join-Path $payload $key
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing intended signing target in MSI: $Name (File $key, not extracted as $path)" }
            $path
        }
    }
    foreach ($file in 'OpenSSHServerPNManager.exe', 'OpenSSHServerPNManager.exe.config') {
        foreach ($packaged in Get-PayloadFile $file) {
            if ((Get-FileHash $packaged -Algorithm SHA256).Hash -ne (Get-FileHash (Join-Path $ManagerDir $file) -Algorithm SHA256).Hash) {
                throw "MSI payload differs from the tested manager: $file"
            }
        }
        Write-Host "PASS: MSI contains the exact tested $file."
    }
    # On every build, not only signed tags: a name that no longer maps to an extracted file fails here first.
    $required = 'libcrypto.dll','scp.exe','ssh-keygen.exe','ssh-agent.exe','OpenSSHServerPNManager.exe',
        'sftp-server.exe','ssh-shellhost.exe','sshd-auth.exe','sshd-session.exe','sshd.exe',
        'ssh.exe','sftp.exe','ssh-add.exe','ssh-keyscan.exe','ssh-sk-helper.exe','ssh-pkcs11-helper.exe'
    foreach ($name in $required) { Get-PayloadFile $name | Out-Null }
    Write-Host "PASS: MSI contains all $($required.Count) intended signing targets."
    if ($RequireSignatures) {
        $targets = @(Get-ChildItem $payload -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' } | ForEach-Object FullName)
        & (Join-Path $PSScriptRoot 'Test-Authenticode.ps1') -Path (@($Msi) + $targets)
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected extraction directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
