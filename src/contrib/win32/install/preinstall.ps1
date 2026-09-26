# Runs inside the OpenSSH MSI as a deferred custom action (LocalSystem) right after
# RemoveExistingProducts: after an installed package has been removed (install, upgrade), or at
# the start of an uninstall, before the services are stopped and the files are removed (this
# includes the nested uninstall of this package during a later upgrade). openssh.wixproj embeds
# this file (base64) into the package; product.wxs runs it through powershell.exe. Every line
# written here lands in the msiexec log, prefixed with "preinstall:".
#
# 1. Stops the sshd and ssh-agent services, whoever registered them (this package, an older
#    package, the ZIP install, or the in-box Windows capability).
# 2. Ends leftover OpenSSH processes that would keep files locked: server processes running from
#    this package's folder, the in-box folder or the folder of the registered sshd service, and
#    client tools running from this package's folder. Other OpenSSH builds (Cygwin, MSYS2, Git)
#    are left alone. The process tree that hosts this installation (an administrator running
#    msiexec inside an SSH session) is kept. When only a feature is removed (REMOVE=Server or
#    REMOVE=Client), only that feature's service and processes are touched.
# 3. On install, upgrade and repair (not on uninstall or feature removal): removes the in-box
#    "OpenSSH Server" Windows capability (KEEP_INBOX_OPENSSH=1 skips this) and re-applies the
#    sshd.exe process mitigation that the removal deletes. When Windows finishes that removal
#    only at the next restart, a one-time startup task re-applies the mitigation after that
#    restart and deletes itself.
# 4. On uninstall: deletes that startup task if it has not run yet.
#
# Phase "firewall" (a second deferred action, after the firewall rule has been created): sets the
# network profiles of the sshd rule. FIREWALL_PROFILES lists them (domain, private, public, all);
# when it is empty, Windows Server gets all profiles and Windows client editions get Domain and
# Private only, so a laptop on public Wi-Fi does not expose SSH.
#
# Every step is best effort: the script always exits 0 and never blocks an install (product.wxs
# also ignores its exit code). Written for Windows PowerShell 2.0 (Windows 7) and later.
param(
    [string]$InstallFolder = '',
    [string]$Remove = '',
    [string]$KeepInbox = '',
    [string]$Phase = 'pre',
    [string]$FirewallProfiles = '',
    [string]$ProductType = ''
)
$ErrorActionPreference = 'Continue'
function Log([string]$m) { Write-Output ("preinstall: " + $m) }
trap {
    Log ("warning: unexpected error, continuing without the rest of the cleanup: " + $_.Exception.Message)
    exit 0
}

if ($Phase -eq 'firewall') {
    $ruleName = 'OpenSSH SSH Server Preview (sshd)'   # FirewallException/@Name in server.wxs
    $mask = 0
    $requested = @($FirewallProfiles.ToLower() -split '[,; ]+' | Where-Object { $_ -ne '' })
    foreach ($p in $requested) {
        switch ($p) { 'domain' { $mask = $mask -bor 1 } 'private' { $mask = $mask -bor 2 } 'public' { $mask = $mask -bor 4 } 'all' { $mask = 0x7FFFFFFF } default { Log ("warning: FIREWALL_PROFILES: unknown profile '" + $p + "' ignored") } }
    }
    if ($mask -eq 0) {
        # MsiNTProductType: 1 = workstation (Windows 10/11), 2 = domain controller, 3 = server
        if ($ProductType -eq '1') { $mask = 3; $why = 'Windows client edition: Domain and Private networks' } else { $mask = 0x7FFFFFFF; $why = 'Windows Server: all networks' }
    } else { $why = 'FIREWALL_PROFILES=' + $FirewallProfiles }
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        $found = 0
        foreach ($rule in $policy.Rules) {
            if ($rule.Name -eq $ruleName -and $rule.Direction -eq 1) { $rule.Profiles = $mask; $found++ }
        }
        if ($found -gt 0) { Log ("firewall rule '" + $ruleName + "' set to profiles 0x" + ('{0:X}' -f $mask) + " (" + $why + ")") }
        else { Log ("warning: firewall rule '" + $ruleName + "' not found; profiles unchanged") }
    } catch {
        Log ("warning: could not set the firewall rule's profiles: " + $_.Exception.Message)
    }
    exit 0
}

$uninstall = ($Remove -eq 'ALL')
# REMOVE=Server, REMOVE=Client: only that feature's files go away, so only its services and
# processes are touched, and the in-box server is left alone.
$featureRemoval = ($Remove -ne '' -and -not $uninstall)
$removedFeatures = @($Remove -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
$touchServer = (-not $featureRemoval) -or ($removedFeatures -contains 'Server')
$touchClient = (-not $featureRemoval) -or ($removedFeatures -contains 'Client')
# ssh-agent, scp and ssh-keygen belong to both features (component group Shared).
$touchShared = (-not $featureRemoval) -or ($touchServer -and $touchClient)
# 32-bit PowerShell (x86 package on 64-bit Windows) reaches the native System32 through Sysnative.
$sysNative = Join-Path $env:SystemRoot 'System32'
if ($env:PROCESSOR_ARCHITEW6432) { $sysNative = Join-Path $env:SystemRoot 'Sysnative' }
$folder = $InstallFolder.TrimEnd('\')
$inboxFolder = Join-Path $env:SystemRoot 'System32\OpenSSH'   # as running processes report it
$inboxSshd = Join-Path $sysNative 'OpenSSH\sshd.exe'          # as this process reaches the file
$dism = Join-Path $sysNative 'dism.exe'
$reg = Join-Path $sysNative 'reg.exe'
$taskName = 'OpenSSH Restore sshd Mitigation'
# Image File Execution Options is shared between the 32-bit and 64-bit registry views.
$ifeoKey = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe'
$mitigationHex = '00000000000000000000000000000000000010'   # same value as SSHDInstallFlagComponent in server.wxs
Log ("mode=" + $(if ($uninstall) { 'uninstall' } elseif ($featureRemoval) { 'feature removal (REMOVE=' + $Remove + ')' } else { 'install' }) + " folder='" + $folder + "' KEEP_INBOX_OPENSSH='" + $KeepInbox + "' user=" + [Security.Principal.WindowsIdentity]::GetCurrent().Name)

function Get-ServiceImageDir([string]$name) {
    $image = ''
    try { $image = [string](Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $name) -ErrorAction Stop).ImagePath } catch { return '' }
    $image = $image.Trim()
    if ($image.StartsWith('"')) {
        $image = $image.Substring(1)
        $q = $image.IndexOf('"')
        if ($q -ge 0) { $image = $image.Substring(0, $q) }
    } else {
        $e = $image.ToLower().IndexOf('.exe')
        if ($e -ge 0) { $image = $image.Substring(0, $e + 4) }
    }
    if ($image -eq '') { return '' }
    return (Split-Path -Path $image -Parent)
}

function Test-Mitigation {
    & $reg query $ifeoKey /v MitigationOptions 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Get-TaskFolder {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    return $svc.GetFolder('\')
}

function Remove-MitigationTask {
    try {
        $root = Get-TaskFolder
        $null = $root.GetTask($taskName)
        $root.DeleteTask($taskName, 0)
        Log ("deleted the startup task '" + $taskName + "'")
    } catch { }
}

function Register-MitigationTask {
    # cmd parses "a || b & c" as "(a || b) & c": write the value only when it is missing, then
    # always delete the task. Runs as SYSTEM at the first startup, before anyone can log on.
    $arguments = '/c reg query "' + $ifeoKey + '" /v MitigationOptions >nul 2>&1 || reg add "' + $ifeoKey + '" /v MitigationOptions /t REG_BINARY /d ' + $mitigationHex + ' /f & schtasks /Delete /TN "' + $taskName + '" /F'
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $root = $svc.GetFolder('\')
        $def = $svc.NewTask(0)
        $def.RegistrationInfo.Description = 'Created by the OpenSSH installer. Windows finishes removing the in-box OpenSSH Server at this restart and deletes the sshd.exe process mitigation (Image File Execution Options) with it; this task puts the mitigation back if it is missing, then deletes itself.'
        $def.Settings.Enabled = $true
        $def.Settings.StartWhenAvailable = $true
        $def.Settings.DisallowStartIfOnBatteries = $false
        $def.Settings.StopIfGoingOnBatteries = $false
        $def.Settings.ExecutionTimeLimit = 'PT10M'
        $null = $def.Triggers.Create(8)    # TASK_TRIGGER_BOOT
        $action = $def.Actions.Create(0)   # TASK_ACTION_EXEC
        $action.Path = Join-Path $env:SystemRoot 'System32\cmd.exe'
        $action.Arguments = $arguments
        $null = $root.RegisterTaskDefinition($taskName, $def, 6, 'SYSTEM', $null, 5)   # CREATE_OR_UPDATE, service account
        Log ("registered the one-time startup task '" + $taskName + "' to re-apply the sshd.exe process mitigation after the restart")
    } catch {
        Log ("warning: could not register the startup task: " + $_.Exception.Message + ". After the next restart, run: reg add `"" + $ifeoKey + "`" /v MitigationOptions /t REG_BINARY /d " + $mitigationHex)
    }
}

# Folders whose server processes this package replaces, read before anything is stopped.
$serverDirs = @()
foreach ($d in @($folder, $inboxFolder, (Get-ServiceImageDir 'sshd'), (Get-ServiceImageDir 'ssh-agent'))) {
    if ($d -and $d.Trim() -ne '') {
        $d = $d.TrimEnd('\')
        $known = $false
        foreach ($x in $serverDirs) { if ([string]::Equals($x, $d, [StringComparison]::OrdinalIgnoreCase)) { $known = $true } }
        if (-not $known) { $serverDirs += $d }
    }
}
Log ("server folders handled: " + ($serverDirs -join '; '))

# 1. services
foreach ($name in @('sshd', 'ssh-agent')) {
    if ($name -eq 'sshd' -and -not $touchServer) { continue }
    if ($name -eq 'ssh-agent' -and -not $touchShared) { continue }
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    $image = ''
    try { $image = [string](Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $name) -ErrorAction Stop).ImagePath } catch { }
    Log ("service " + $name + ": " + $svc.Status + " ImagePath=" + $image)
    if (-not $uninstall -and $folder -ne '') {
        $dir = Get-ServiceImageDir $name
        if ($dir -ne '' -and -not [string]::Equals($dir.TrimEnd('\'), $folder, [StringComparison]::OrdinalIgnoreCase)) {
            Log ("service " + $name + " is registered from " + $dir + "; this package takes the registration over. Files there are not removed.")
        }
    }
    if ($svc.Status -eq 'Stopped') { continue }
    try {
        Stop-Service -Name $name -Force -ErrorAction Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        Log ("service " + $name + " stopped")
    } catch {
        Log ("warning: service " + $name + " did not stop cleanly (" + $_.Exception.Message + "); its processes are ended below")
    }
}

# 2. leftover processes
$serverExes = @('sshd.exe', 'sshd-session.exe', 'sshd-auth.exe', 'sftp-server.exe', 'ssh-shellhost.exe')
$clientExes = @('ssh.exe', 'sftp.exe', 'ssh-add.exe', 'ssh-keyscan.exe', 'ssh-sk-helper.exe', 'ssh-pkcs11-helper.exe')
$sharedExes = @('ssh-agent.exe', 'scp.exe', 'ssh-keygen.exe')
$all = @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)
if ($all.Count -eq 0) { Log "warning: process list unavailable; files held open by running OpenSSH processes are replaced at the next restart" }
$byId = @{}
foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }

# Keep every ancestor of a running msiexec.exe (the client that drives this installation) and of
# this script. A parent that started later than its child is a reused PID, not an ancestor.
$keep = @{}
foreach ($p in $all) {
    if ([string]$p.Name -ne 'msiexec.exe' -and [int]$p.ProcessId -ne $PID) { continue }
    $cur = $p
    $hops = 0
    while ($cur -and $hops -lt 64) {
        $keep[[int]$cur.ProcessId] = $true
        $parent = $byId[[int]$cur.ParentProcessId]
        if (-not $parent -or [int]$parent.ProcessId -eq [int]$cur.ProcessId) { break }
        if ($parent.CreationDate -and $cur.CreationDate -and ([string]$parent.CreationDate -gt [string]$cur.CreationDate)) { break }
        $cur = $parent
        $hops++
    }
}

$killed = @()
foreach ($p in $all) {
    $name = [string]$p.Name
    $path = [string]$p.ExecutablePath
    $isServer = ($serverExes -contains $name)
    $isClient = ($clientExes -contains $name)
    $isShared = ($sharedExes -contains $name)
    if ((-not $isServer -and -not $isClient -and -not $isShared) -or $path -eq '') { continue }
    $dir = (Split-Path -Path $path -Parent).TrimEnd('\')
    $inFolder = ($folder -ne '' -and [string]::Equals($dir, $folder, [StringComparison]::OrdinalIgnoreCase))
    $target = $false
    if ($isServer -and $touchServer) { foreach ($d in $serverDirs) { if ([string]::Equals($dir, $d, [StringComparison]::OrdinalIgnoreCase)) { $target = $true } } }
    if ($isClient -and $touchClient -and $inFolder) { $target = $true }
    if ($isShared -and $touchShared -and $inFolder) { $target = $true }
    if (-not $target) { continue }
    $id = [int]$p.ProcessId
    if ($keep[$id]) {
        Log ("keeping " + $name + " (PID " + $id + "): it hosts this installation. Files it holds open are replaced at the next restart.")
        continue
    }
    Log ("terminating " + $name + " (PID " + $id + ") " + $path)
    try {
        Stop-Process -Id $id -Force -ErrorAction Stop
        $killed += $id
    } catch {
        if (Get-Process -Id $id -ErrorAction SilentlyContinue) { Log ("warning: could not terminate PID " + $id + ": " + $_.Exception.Message) }
        else { Log ("PID " + $id + " had already exited") }
    }
}
if ($killed.Count -gt 0) {
    Wait-Process -Id $killed -Timeout 15 -ErrorAction SilentlyContinue
    Log ("terminated " + $killed.Count + " process(es)")
}

# 3. in-box OpenSSH Server (Windows capability OpenSSH.Server~~~~0.0.1.0)
# The in-box server registers a service also named "sshd"; this package's ServiceInstall takes
# that single registration over and points it at the installed binaries, so there is never a
# second competing service. Removing the capability clears the unused files and stops Windows
# servicing of the capability (updates to it) from pointing the sshd service back at the in-box
# binary. Best effort.
if (-not $uninstall -and -not $featureRemoval -and (Test-Path -LiteralPath $inboxSshd)) {
    $state = ''
    $info = & $dism /Online /Get-CapabilityInfo /CapabilityName:OpenSSH.Server~~~~0.0.1.0 2>&1 | Out-String
    foreach ($line in ($info -split "`r?`n")) { if ($line -match '^\s*State\s*:\s*(.+?)\s*$') { $state = $matches[1] } }
    Log ("in-box OpenSSH Server file present (" + $inboxSshd + "); capability state: " + $(if ($state) { $state } else { 'unknown' }))
    $restartPending = ($state -eq 'Uninstall Pending')
    $removed = $false
    if ($KeepInbox -eq '1') {
        Log "KEEP_INBOX_OPENSSH=1; leaving the in-box capability in place. Its sshd registration is taken over by this package."
    } elseif ($state -eq 'Installed') {
        Log "removing the OpenSSH.Server Windows capability"
        $output = & $dism /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /NoRestart 2>&1 | Out-String
        $code = $LASTEXITCODE
        # progress bars carry no letters; keep the messages only
        foreach ($line in ($output -split "`r?`n")) { if ($line -match '[A-Za-z]') { Log ("dism: " + $line.Trim()) } }
        if ($code -eq 0) {
            $removed = $true
            Log "in-box OpenSSH Server removed"
        } elseif ($code -eq 3010) {
            $removed = $true
            $restartPending = $true
            Log "in-box OpenSSH Server removed; Windows finishes clearing its files at the next restart"
        } else {
            Log ("warning: dism.exe returned " + $code + "; leaving the in-box files in place. This package's sshd service points at the installed binaries, so the install continues. Remove the leftovers later with: Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        }
    } else {
        Log "capability not in the 'Installed' state (already pending removal, or an orphaned file); nothing to remove"
    }
    # The capability owns the sshd.exe mitigation key and deletes it on removal, while this
    # package's own component skipped writing it because the key existed when the install began.
    if ($removed -or $restartPending) {
        if (Test-Mitigation) {
            Log "sshd.exe process mitigation (Image File Execution Options) present"
        } else {
            & $reg add $ifeoKey /v MitigationOptions /t REG_BINARY /d $mitigationHex /f 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Log "re-applied the sshd.exe process mitigation (Image File Execution Options) removed with the in-box server" }
            else { Log ("warning: could not re-apply the sshd.exe process mitigation (reg.exe exit " + $LASTEXITCODE + ")") }
        }
        if ($restartPending) { Register-MitigationTask }
    }
}

# 4. uninstall: nothing left behind
if ($uninstall) { Remove-MitigationTask }

Log "done"
exit 0
