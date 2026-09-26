# Runs inside the OpenSSH MSI through powershell.exe; product.wxs runs it in several steps, chosen
# by -Phase. openssh.wixproj embeds this file (base64) as two scripts, because powershell.exe gets
# the script on its command line (at most 32767 characters): one without the "#region firewall"
# parts (phases "pre" and "sessions") and one without the "#region pre" parts (the firewall and port
# phases). Comment lines, blank lines and indentation are left out of both. Every line written here
# lands in the msiexec log, prefixed with "preinstall:". Written for Windows PowerShell 2.0
# (Windows 7) and later: no PowerShell 3+ syntax or cmdlets (tests\preinstall.Tests.ps1 checks for
# the usual ones).
#
# Phase "pre" (the default; deferred, LocalSystem, right after RemoveExistingProducts): after an
# installed package has been removed (install, upgrade), or at the start of an uninstall, before the
# services are stopped and the files are removed (this includes the nested uninstall of this package
# during a later upgrade).
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
# Phase "sessions" (immediate, before InstallValidate, only with ACTIVE_SESSIONS=abort): exits 1,
# which stops the installation before anything has changed, when step 2 above would end an SSH
# session (an sshd-session.exe process that does not host this installation).
#
# The sshd firewall rule belongs to the package: removing the old package deletes it, and the new
# package creates it again with port 22. These phases carry its settings over an upgrade or repair:
# - "fwsave" (deferred, LocalSystem; InstallExecute runs it before RemoveExistingProducts removes the
#   old package): when a package of this series is installed (-Previous keep), writes the rule's
#   LocalPorts, Profiles, Enabled and RemoteAddresses to HKLM\SOFTWARE\OpenSSH\Installer, value
#   FirewallRule (only SYSTEM and Administrators can write there). The rule of OpenSSH Server Manager
#   counts when the package's rule is missing. On a fresh install, only removes a leftover record.
# - "firewall" (deferred, after the WiX firewall action has created the rule): sets the rule.
#   Networks: FIREWALL_PROFILES, else the saved ones, else all on Windows Server and Domain plus
#   Private on client editions. Ports: SSHD_PORT, else the saved ones, else 22 (server.wxs). Enabled
#   and remote addresses: the saved ones, else enabled and any.
# - "fwcommit" (commit): deletes the record once the installation has succeeded.
# - "fwrollback" (rollback): when the installation fails, puts the saved settings back on the rule
#   that the rolled-back old package re-created, and deletes the record.
#
# Phase "port" (deferred, after StartServices, only with SSHD_PORT): sets "Port <n>" in
# %ProgramData%\ssh\sshd_config (the previous file is kept as sshd_config.bak.<date>-<time>) and
# restarts sshd. If sshd then does not listen on the port, the previous file is put back, sshd is
# restarted and the firewall rule gets the port(s) of that file.
#
# Except "sessions", every phase is best effort: the script exits 0 and never blocks an
# installation (product.wxs also ignores its exit code).
param(
    [string]$InstallFolder = '',
    [string]$Remove = '',
    [string]$KeepInbox = '',
    [string]$Phase = 'pre',
    [string]$FirewallProfiles = '',
    [string]$ProductType = '',
    [string]$SshdPort = '',
    [string]$Previous = ''
)
$ErrorActionPreference = 'Continue'
function Log([string]$m) { Write-Output ("preinstall: " + $m) }
trap {
    if ($Phase -eq 'sessions') {
        Log ("error: the check for open SSH sessions failed (" + $_.Exception.Message + "). ACTIVE_SESSIONS=abort stops the installation; nothing has been changed.")
        exit 1
    }
    Log ("warning: unexpected error, continuing without the rest of this step: " + $_.Exception.Message)
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
# 32-bit PowerShell reaches the native System32 through Sysnative. WixQuietExec runs in a 32-bit
# custom action host, so this script runs in 32-bit PowerShell on 64-bit Windows.
$sysNative = Join-Path $env:SystemRoot 'System32'
if ($env:PROCESSOR_ARCHITEW6432) { $sysNative = Join-Path $env:SystemRoot 'Sysnative' }
$folder = $InstallFolder.TrimEnd('\')
$inboxFolder = Join-Path $env:SystemRoot 'System32\OpenSSH'   # as running processes report it
$inboxSshd = Join-Path $sysNative 'OpenSSH\sshd.exe'          # as this process reaches the file
$dism = Join-Path $sysNative 'dism.exe'
# The native reg.exe: Image File Execution Options and the saved firewall record are read and
# written in the native registry view, whatever the bitness of this PowerShell.
$reg = Join-Path $sysNative 'reg.exe'

#region pre   (openssh.wixproj leaves this part out of the script of the firewall steps)
$taskName = 'OpenSSH Restore sshd Mitigation'
$ifeoKey = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe'
$mitigationHex = '00000000000000000000000000000000000010'   # same value as SSHDInstallFlagComponent in server.wxs

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

function Test-InDirs([string]$dir, $dirs) {
    foreach ($x in $dirs) { if ([string]::Equals($x, $dir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

# Folders whose server processes this package replaces: its own, the in-box one and those of the
# registered services, read before anything is stopped.
function Get-ServerDirs {
    $dirs = @()
    foreach ($d in @($folder, $inboxFolder, (Get-ServiceImageDir 'sshd'), (Get-ServiceImageDir 'ssh-agent'))) {
        if ($d -and $d.Trim() -ne '' -and -not (Test-InDirs $d $dirs)) { $dirs += $d.TrimEnd('\') }
    }
    return $dirs
}

# Process IDs to keep: every ancestor of a running msiexec.exe (the client that drives this
# installation) and of this script. A parent that started later than its child is a reused PID,
# not an ancestor.
function Get-KeepSet($all, [int]$self = $PID) {
    $byId = @{}
    foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }
    $keep = @{}
    foreach ($p in $all) {
        if ([string]$p.Name -ne 'msiexec.exe' -and [int]$p.ProcessId -ne $self) { continue }
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
    return $keep
}

# PIDs of the sshd-session.exe processes (one or two per SSH connection) that phase "pre" would
# end: running from one of $dirs, or from a folder this account cannot read (a standard user does
# not see the path of another account's process), and not hosting this installation.
function Get-OpenSessions($all, $keep, $dirs) {
    $ids = @()
    foreach ($p in $all) {
        if ([string]$p.Name -ne 'sshd-session.exe') { continue }
        $path = [string]$p.ExecutablePath
        if ($path -ne '' -and -not (Test-InDirs (Split-Path -Path $path -Parent) $dirs)) { continue }
        if ($keep[[int]$p.ProcessId]) { continue }
        $ids += [int]$p.ProcessId
    }
    return $ids
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
#endregion pre

#region firewall   (openssh.wixproj leaves this part out of the script of phases "pre" and "sessions")
# ---- firewall rule settings ----
$ruleName = 'OpenSSH SSH Server Preview (sshd)'   # FirewallException/@Name in server.wxs
$altRuleName = 'OpenSSH SSH Server (sshd)'        # OpenSSH Server Manager creates this one when the rule above is missing
$recordKey = 'HKLM\SOFTWARE\OpenSSH\Installer'
$recordValue = 'FirewallRule'
# First line of the rules section that OpenSSH Server Manager keeps in sshd_config (Auth.cs, RegionBegin).
$managerRegion = '# Login methods by user and group, managed on the Authentication tab of OpenSSH Server Manager.'
# The functions below return values and write no log lines (Log output would become part of the
# value); the phases log.

# FIREWALL_PROFILES (domain, private, public, all; comma list) as a NET_FW_PROFILE2 mask, 0 if none.
function Get-ProfileMask([string]$list) {
    $mask = 0
    foreach ($p in @($list.ToLower() -split '[,; ]+' | Where-Object { $_ -ne '' })) {
        switch ($p) { 'domain' { $mask = $mask -bor 1 } 'private' { $mask = $mask -bor 2 } 'public' { $mask = $mask -bor 4 } 'all' { $mask = 0x7FFFFFFF } }
    }
    return $mask
}

function Get-ProfileText([int]$mask) {
    if (($mask -band 7) -eq 7) { return ('all networks (0x' + ('{0:X}' -f $mask) + ')') }
    $l = @()
    if ($mask -band 1) { $l += 'Domain' }
    if ($mask -band 2) { $l += 'Private' }
    if ($mask -band 4) { $l += 'Public' }
    if ($l.Count -eq 0) { $l += 'none' }
    return (($l -join ', ') + ' (0x' + ('{0:X}' -f $mask) + ')')
}

# A TCP port given as digits only (the launch condition lets leading zeros through), 1-65535; 0 for
# anything else.
function ConvertTo-Port([string]$s) {
    $n = 0
    if ($s.Trim() -match '^[0-9]{1,9}$' -and [int]::TryParse($s.Trim(), [ref]$n) -and $n -ge 1 -and $n -le 65535) { return $n }
    return 0
}

# The record is one line: v1|Rule=<name>|LocalPorts=<ports>|Profiles=<mask>|Enabled=<0|1>|RemoteAddresses=<list>.
# Firewall values never contain "|" (Windows stores its rules in the same form).
function ConvertTo-FirewallRecord($r) {
    $enabled = '0'
    if ($r.Enabled) { $enabled = '1' }
    return ('v1|Rule=' + $r.Rule + '|LocalPorts=' + $r.LocalPorts + '|Profiles=' + [int]$r.Profiles + '|Enabled=' + $enabled + '|RemoteAddresses=' + $r.RemoteAddresses)
}

# A hashtable with the valid fields of a record (Rule is always there), or $null. Only the two known
# rule names and plain port, number and address characters are accepted.
function ConvertFrom-FirewallRecord([string]$text) {
    $parts = @($text.Trim() -split '\|')
    if ($parts.Count -lt 2 -or $parts[0] -ne 'v1') { return $null }
    $r = @{}
    foreach ($part in $parts) {
        $i = $part.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $part.Substring(0, $i)
        $v = $part.Substring($i + 1)
        $n = 0
        switch ($k) {
            'Rule' { if ($v -eq $ruleName -or $v -eq $altRuleName) { $r['Rule'] = $v } }
            'LocalPorts' { if ($v -match '^[A-Za-z0-9*,-]{1,1000}$') { $r['LocalPorts'] = $v } }
            'Profiles' { if ($v -match '^[0-9]{1,10}$' -and [int]::TryParse($v, [ref]$n) -and $n -gt 0) { $r['Profiles'] = $n } }
            'Enabled' { if ($v -eq '1') { $r['Enabled'] = $true } elseif ($v -eq '0') { $r['Enabled'] = $false } }
            'RemoteAddresses' { if ($v -match '^[A-Za-z0-9*.,:/-]{1,4000}$') { $r['RemoteAddresses'] = $v } }
        }
    }
    if (-not $r.ContainsKey('Rule')) { return $null }
    return $r
}

function Format-FirewallRecord($r) {
    $l = @()
    if ($r.ContainsKey('LocalPorts')) { $l += ('ports ' + $r['LocalPorts']) }
    if ($r.ContainsKey('Profiles')) { $l += ('networks ' + (Get-ProfileText $r['Profiles'])) }
    if ($r.ContainsKey('Enabled')) { if ($r['Enabled']) { $l += 'enabled' } else { $l += 'disabled' } }
    if ($r.ContainsKey('RemoteAddresses')) { $l += ('remote addresses ' + $r['RemoteAddresses']) }
    return ($l -join ', ')
}

# The first inbound rule of this name, or $null. Rules.Item is one call; all rules are walked only
# when that one is an outbound rule of the same name.
function Get-InboundRule($policy, [string]$name) {
    $rule = $null
    try { $rule = $policy.Rules.Item($name) } catch { return $null }
    if ($rule -and $rule.Direction -eq 1) { return $rule }
    foreach ($x in $policy.Rules) { if ($x.Name -eq $name -and $x.Direction -eq 1) { return $x } }
    return $null
}

# The settings of the sshd rule as a record hashtable, or $null. The rule of OpenSSH Server Manager
# counts when the package's rule is missing, unless it allows the in-box sshd (that rule belongs to
# the Windows capability).
function Read-FirewallRecord($policy) {
    foreach ($name in @($ruleName, $altRuleName)) {
        $rule = Get-InboundRule $policy $name
        if (-not $rule) { continue }
        if ($name -eq $altRuleName -and [string]$rule.ApplicationName -match '\\System32\\OpenSSH\\sshd\.exe$') { continue }
        return @{ Rule = $name; LocalPorts = [string]$rule.LocalPorts; Profiles = [int]$rule.Profiles; Enabled = [bool]$rule.Enabled; RemoteAddresses = [string]$rule.RemoteAddresses }
    }
    return $null
}

# Sets the given settings on every inbound rule of this name. Returns @{ Rules = <number of rules>;
# Errors = <the settings that could not be set> }.
function Set-RuleSettings($policy, [string]$name, $s) {
    $result = @{ Rules = 0; Errors = @() }
    foreach ($rule in $policy.Rules) {
        if ($rule.Name -ne $name -or $rule.Direction -ne 1) { continue }
        foreach ($k in @('RemoteAddresses', 'LocalPorts', 'Profiles', 'Enabled')) {
            if (-not $s.ContainsKey($k)) { continue }
            try { $rule.$k = $s[$k] } catch { $result['Errors'] += ($k + ' = ' + $s[$k] + ': ' + $_.Exception.Message) }
        }
        $result['Rules'] = $result['Rules'] + 1
    }
    return $result
}

function Get-SavedRecord {
    $out = & $reg query $recordKey /v $recordValue 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { return '' }
    foreach ($line in ($out -split "`r?`n")) { if ($line -match ('^\s*' + $recordValue + '\s+REG_SZ\s+(.*?)\s*$')) { return $matches[1] } }
    return ''
}

function Save-Record([string]$text) {
    & $reg add $recordKey /v $recordValue /t REG_SZ /d $text /f 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Remove-Record { & $reg delete $recordKey /f 2>&1 | Out-Null }

# ---- sshd_config ----

# sshd_config text with "Port <port>", following OpenSSH Server Manager (SshdConfig.SetFirst): the
# first top-level Port line gets the port (a comment at its end stays), else the first "#Port"
# example (sshd_config_default has "#Port 22"; prose such as "# Port forwarding" has a space after
# the #), else the line goes before the first Include line or the first Match block. Further Port
# lines stay: sshd listens on each of them. Line endings and a final line break are kept.
function Set-SshdConfigPortText([string]$text, [int]$port) {
    $nl = "`n"
    if ($text.Contains("`r`n")) { $nl = "`r`n" }
    $lines = New-Object System.Collections.ArrayList
    if ($text -ne '') { foreach ($l in ($text -split "`r?`n")) { $null = $lines.Add($l) } }
    $final = ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '')
    if ($final) { $lines.RemoveAt($lines.Count - 1) }
    $new = 'Port ' + $port
    $end = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*Match(\s|$)' -or $lines[$i].Trim() -eq $managerRegion) { $end = $i; break } }
    $at = -1
    for ($i = 0; $i -lt $end -and $at -lt 0; $i++) {
        if ($lines[$i] -match '^\s*Port(\s*=\s*|\s+)[^#]*(#.*)?$') {
            $lines[$i] = $new
            if ($matches[2]) { $lines[$i] = $new + ' ' + $matches[2] }
            $at = $i
        }
    }
    for ($i = 0; $i -lt $end -and $at -lt 0; $i++) { if ($lines[$i] -match '^\s*#Port(\s|=)') { $lines[$i] = $new; $at = $i } }
    if ($at -lt 0) {
        $at = $end
        for ($i = 0; $i -lt $end; $i++) { if ($lines[$i] -match '^\s*Include(\s|=)') { $at = $i; break } }
        if ($at -eq $lines.Count) { $final = $true }
        $lines.Insert($at, $new)
        # a blank line between the new line and the Match block that follows it
        if ($at -eq $end -and $at + 1 -lt $lines.Count) { $lines.Insert($at + 1, '') }
    }
    $out = ($lines -join $nl)
    if ($final) { $out += $nl }
    return $out
}

# The ports sshd listens on with this configuration: top-level Port lines, else the ports named
# by ListenAddress lines, else 22.
function Get-SshdConfigPorts([string]$text) {
    $ports = @()
    $listen = @()
    foreach ($l in ($text -split "`r?`n")) {
        if ($l -match '^\s*Match(\s|$)' -or $l.Trim() -eq $managerRegion) { break }
        if ($l -match '^\s*Port(?:\s*=\s*|\s+)([0-9]{1,5})\s*(#.*)?$') { $p = [string][int]$matches[1]; if ($ports -notcontains $p) { $ports += $p } }
        elseif ($l -match '^\s*ListenAddress(?:\s*=\s*|\s+)(?:\[[^\]]*\]|[^\s:#\[]+):([0-9]{1,5})(\s|#|$)') { $p = [string][int]$matches[1]; if ($listen -notcontains $p) { $listen += $p } }
    }
    if ($ports.Count -eq 0) { $ports = $listen }
    if ($ports.Count -eq 0) { $ports = @('22') }
    return $ports
}

# sshd_config.bak.yyyyMMdd-HHmmss, with -2, -3 ... when a backup of that second exists already
# (the names OpenSSH Server Manager uses, so its Restore dialog lists them).
function Get-BackupPath([string]$path, [DateTime]$now) {
    $b = $path + '.bak.' + $now.ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)
    if (-not (Test-Path -LiteralPath $b)) { return $b }
    $i = 2
    while (Test-Path -LiteralPath ($b + '-' + $i)) { $i++ }
    return ($b + '-' + $i)
}

function Copy-Dacl([string]$from, [string]$to) {
    $fs = New-Object Security.AccessControl.FileSecurity
    $fs.SetSecurityDescriptorSddlForm([IO.File]::GetAccessControl($from).GetSecurityDescriptorSddlForm('Access'), 'Access')
    [IO.File]::SetAccessControl($to, $fs)
}

# Writes the file through a temporary file that ReplaceFile swaps in: the new file keeps the
# permissions of the old one, which becomes $backup. Where that fails, copies the backup and
# writes in place, which keeps the permissions as well. Returns how the file was written.
function Write-ConfigText([string]$path, [string]$text, [string]$backup) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $enc = New-Object Text.UTF8Encoding($bom)
    $tmp = $path + '.new-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    try {
        [IO.File]::WriteAllText($tmp, $text, $enc)
        [IO.File]::Replace($tmp, $path, $backup)
        return 'replaced'
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        if (-not (Test-Path -LiteralPath $backup)) { [IO.File]::WriteAllBytes($backup, $bytes); Copy-Dacl $path $backup }
        if (-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllBytes($path, $bytes); Copy-Dacl $backup $path }
        [IO.File]::WriteAllText($path, $text, $enc)
        return 'in place'
    }
}

# True when the sshd service runs and something listens on the port, still after 3 more seconds
# (sshd stops by itself when it cannot bind any address).
function Test-SshdListening([int]$port) {
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
        $listening = $false
        foreach ($ep in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()) { if ($ep.Port -eq $port) { $listening = $true } }
        if ($svc -and $svc.Status -eq 'Running' -and $listening) {
            Start-Sleep -Seconds 3
            $svc.Refresh()
            return ($svc.Status -eq 'Running')
        }
    }
    return $false
}
#endregion firewall

if ($Phase -eq 'functions') { return }   # tests\preinstall.Tests.ps1 dot-sources the functions

#region firewall
if ($Phase -eq 'fwsave') {
    $old = Get-SavedRecord
    if ($Previous -ne 'keep') {
        if ($old -ne '') { Remove-Record; Log ("removed a saved firewall record left by an interrupted installation: " + $old) }
        Log "fresh install: the firewall rule gets this package's defaults"
        exit 0
    }
    $r = $null
    try { $r = Read-FirewallRecord (New-Object -ComObject HNetCfg.FwPolicy2) } catch { Log ("warning: could not read the firewall rules (" + $_.Exception.Message + "); the new rule gets the defaults") }
    if (-not $r) {
        if ($old -ne '') { Remove-Record }
        Log ("no inbound firewall rule '" + $ruleName + "' or '" + $altRuleName + "' (other than the in-box server's) to keep; the new rule gets the defaults")
        exit 0
    }
    $text = ConvertTo-FirewallRecord $r
    $check = ConvertFrom-FirewallRecord $text
    foreach ($k in @('LocalPorts', 'Profiles', 'Enabled', 'RemoteAddresses')) {
        if (-not $check.ContainsKey($k)) { Log ("warning: " + $k + " of firewall rule '" + $r.Rule + "' (" + $r[$k] + ") is not kept; the new rule gets the default") }
    }
    if (Save-Record $text) { Log ("saved the settings of firewall rule '" + $r.Rule + "' for the new rule: " + (Format-FirewallRecord $check) + " (" + $recordKey + ")") }
    else { Log ("warning: could not write " + $recordKey + " (reg.exe exit " + $LASTEXITCODE + "); the new rule gets the defaults") }
    exit 0
}

if ($Phase -eq 'fwcommit') {
    if ((Get-SavedRecord) -ne '') { Remove-Record; Log "installation complete: removed the saved firewall settings" }
    exit 0
}

if ($Phase -eq 'fwrollback') {
    $text = Get-SavedRecord
    if ($text -eq '') { exit 0 }
    $saved = ConvertFrom-FirewallRecord $text
    if ($saved -and $saved['Rule'] -eq $ruleName) {
        try {
            $res = Set-RuleSettings (New-Object -ComObject HNetCfg.FwPolicy2) $ruleName $saved
            foreach ($e in $res['Errors']) { Log ("warning: rollback: could not set " + $e) }
            if ($res['Rules'] -gt 0) { Log ("rollback: firewall rule '" + $ruleName + "' set back to " + (Format-FirewallRecord $saved)) }
            else { Log ("warning: rollback: firewall rule '" + $ruleName + "' not found; saved settings: " + (Format-FirewallRecord $saved)) }
        } catch { Log ("warning: rollback: could not set the firewall rule: " + $_.Exception.Message) }
    }
    Remove-Record
    exit 0
}

if ($Phase -eq 'firewall') {
    $saved = $null
    $text = Get-SavedRecord
    if ($text -ne '') {
        $saved = ConvertFrom-FirewallRecord $text
        if (-not $saved) { Log ("warning: ignoring an unreadable saved firewall record: " + $text) }
    }
    $s = @{}
    $notes = @()
    $mask = Get-ProfileMask $FirewallProfiles
    if ($mask -ne 0) { $s['Profiles'] = $mask; $why = 'FIREWALL_PROFILES=' + $FirewallProfiles }
    elseif ($saved -and $saved.ContainsKey('Profiles')) { $s['Profiles'] = $saved['Profiles']; $why = 'kept from the previous installation' }
    # MsiNTProductType: 1 = workstation (Windows 10/11), 2 = domain controller, 3 = server
    elseif ($ProductType -eq '1') { $s['Profiles'] = 3; $why = 'Windows client edition' }
    else { $s['Profiles'] = 0x7FFFFFFF; $why = 'Windows Server' }
    $notes += ('networks ' + (Get-ProfileText $s['Profiles']) + ': ' + $why)
    $port = 0
    if ($SshdPort -ne '') {
        $port = ConvertTo-Port $SshdPort
        if ($port -eq 0) { Log ("warning: SSHD_PORT '" + $SshdPort + "' is not a port number; ignored") }
    }
    if ($port -ne 0) { $s['LocalPorts'] = [string]$port; $notes += ('port ' + $port + ': SSHD_PORT') }
    elseif ($saved -and $saved.ContainsKey('LocalPorts')) { $s['LocalPorts'] = $saved['LocalPorts']; $notes += ('ports ' + $saved['LocalPorts'] + ': kept') }
    if ($saved -and $saved.ContainsKey('Enabled')) {
        $s['Enabled'] = $saved['Enabled']
        if ($saved['Enabled']) { $notes += 'enabled: kept' } else { $notes += 'DISABLED: kept' }
    }
    if ($saved -and $saved.ContainsKey('RemoteAddresses')) { $s['RemoteAddresses'] = $saved['RemoteAddresses']; $notes += ('remote addresses ' + $saved['RemoteAddresses'] + ': kept') }
    if ($saved) { Log ("restoring the settings saved from firewall rule '" + $saved['Rule'] + "'; FIREWALL_PROFILES and SSHD_PORT take precedence") }
    try {
        $res = Set-RuleSettings (New-Object -ComObject HNetCfg.FwPolicy2) $ruleName $s
        foreach ($e in $res['Errors']) { Log ("warning: could not set " + $e) }
        if ($res['Rules'] -gt 0) { Log ("firewall rule '" + $ruleName + "': " + ($notes -join '; ')) }
        else { Log ("warning: firewall rule '" + $ruleName + "' not found; its settings are unchanged") }
    } catch {
        Log ("warning: could not set the firewall rule: " + $_.Exception.Message)
    }
    exit 0
}

if ($Phase -eq 'port') {
    $port = ConvertTo-Port $SshdPort
    if ($port -eq 0) { Log ("warning: SSHD_PORT '" + $SshdPort + "' is not a port number; sshd_config unchanged"); exit 0 }
    $cfgDir = Join-Path $env:ProgramData 'ssh'
    $cfg = Join-Path $cfgDir 'sshd_config'
    if (-not (Test-Path -LiteralPath $cfg)) {
        # sshd creates the file at its first start; this covers a service that did not get that far.
        if (-not (Test-Path -LiteralPath $cfgDir)) {
            $ds = New-Object Security.AccessControl.DirectorySecurity
            $ds.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)', 'Access')
            $null = [IO.Directory]::CreateDirectory($cfgDir, $ds)
        }
        [IO.File]::Copy((Join-Path $folder 'sshd_config_default'), $cfg)
        $fs = New-Object Security.AccessControl.FileSecurity
        $fs.SetSecurityDescriptorSddlForm('D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;AU)', 'Access')
        [IO.File]::SetAccessControl($cfg, $fs)
        Log ("created " + $cfg + " from sshd_config_default (SYSTEM and Administrators: full control, Authenticated Users: read)")
    }
    $text = [IO.File]::ReadAllText($cfg)
    $new = Set-SshdConfigPortText $text $port
    $backup = ''
    if ($new -ceq $text) {
        Log ("sshd_config already has Port " + $port)
    } else {
        $backup = Get-BackupPath $cfg (Get-Date)
        $how = Write-ConfigText $cfg $new $backup
        Log ("sshd_config: Port " + $port + " (written " + $how + "; previous file: " + $backup + ")")
    }
    $others = @(Get-SshdConfigPorts $new | Where-Object { $_ -ne [string]$port })
    if ($others.Count -gt 0) { Log ("sshd_config has further Port lines; sshd also listens on " + ($others -join ', ')) }
    try { Restart-Service -Name sshd -Force -ErrorAction Stop } catch { Log ("warning: restarting sshd: " + $_.Exception.Message) }
    if (Test-SshdListening $port) { Log ("sshd restarted and listens on port " + $port); exit 0 }
    if ($backup -eq '') { Log ("warning: sshd does not listen on port " + $port + " after a restart. Check the OpenSSH/Operational event log."); exit 0 }
    # Back to the previous configuration, so the server stays reachable as before.
    [IO.File]::WriteAllBytes($cfg, [IO.File]::ReadAllBytes($backup))
    try { Restart-Service -Name sshd -Force -ErrorAction Stop } catch { }
    $ports = @(Get-SshdConfigPorts ([IO.File]::ReadAllText($cfg)))
    $fwNote = ''
    try {
        $res = Set-RuleSettings (New-Object -ComObject HNetCfg.FwPolicy2) $ruleName @{ LocalPorts = ($ports -join ',') }
        if ($res['Rules'] -gt 0 -and $res['Errors'].Count -eq 0) { $fwNote = ' The firewall rule allows port ' + ($ports -join ',') + ' again.' }
    } catch { }
    Log ("warning: sshd did not listen on port " + $port + " (port in use, or blocked by a ListenAddress line?). The previous sshd_config is back and sshd was restarted with port " + ($ports -join ',') + "." + $fwNote + " Check the OpenSSH/Operational event log, then set the port with OpenSSH Server Manager.")
    exit 0
}
#endregion firewall

#region pre
if ($Phase -eq 'sessions') {
    if (-not $touchServer) { Log "ACTIVE_SESSIONS=abort: the server feature is not changed; open sessions are not affected"; exit 0 }
    $all = @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)
    $ids = @()
    if ($all.Count -gt 0) {
        $ids = @(Get-OpenSessions $all (Get-KeepSet $all) @(Get-ServerDirs))
    } else {
        # No process tree: count every sshd-session.exe.
        foreach ($p in @(Get-Process -Name 'sshd-session' -ErrorAction SilentlyContinue)) { $ids += $p.Id }
    }
    if ($ids.Count -gt 0) {
        Log ("error: ACTIVE_SESSIONS=abort and " + $ids.Count + " SSH session process(es) are running (sshd-session.exe, PID " + ($ids -join ', ') + "). The installation stops before anything has been changed; run it again when no one is connected, or without ACTIVE_SESSIONS=abort to end the sessions.")
        exit 1
    }
    Log "ACTIVE_SESSIONS=abort: no open SSH session; the installation continues"
    exit 0
}

# ---- phase "pre" ----
if ($Phase -ne 'pre') { Log ("warning: unknown phase '" + $Phase + "'; nothing done"); exit 0 }
Log ("mode=" + $(if ($uninstall) { 'uninstall' } elseif ($featureRemoval) { 'feature removal (REMOVE=' + $Remove + ')' } else { 'install' }) + " folder='" + $folder + "' KEEP_INBOX_OPENSSH='" + $KeepInbox + "' user=" + [Security.Principal.WindowsIdentity]::GetCurrent().Name)

$serverDirs = @(Get-ServerDirs)
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
$keep = Get-KeepSet $all

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
    if ($isServer -and $touchServer -and (Test-InDirs $dir $serverDirs)) { $target = $true }
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
#endregion pre

Log ("warning: phase '" + $Phase + "' is not part of this script; nothing done")
exit 0
