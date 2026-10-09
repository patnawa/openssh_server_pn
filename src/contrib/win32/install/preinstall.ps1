# Runs inside the OpenSSH MSI through powershell.exe; product.wxs runs it in several steps, chosen
# by -Phase. openssh.wixproj embeds this file (base64) as two scripts, because powershell.exe gets
# the script on its command line (at most 32767 characters): one without the "#region firewall"
# parts (phases "pre" and "sessions") and one without the "#region pre" parts (the firewall and port
# phases). Comment lines, blank lines and indentation are left out of both. Every line written here
# lands in the msiexec log, prefixed with "preinstall:". Written for Windows PowerShell 2.0
# (Windows 7, Windows Server 2008 R2) and later: no PowerShell 3+ syntax or cmdlets
# (tests\preinstall.Tests.ps1 checks for the usual ones; the CI runs every installer scenario with
# the steps on the 2.0 engine). product.wxs starts powershell.exe with -InputFormat None, without
# which PowerShell 2.0 waits for the end of the standard input that WixQuietExec keeps open.
#
# Phase "pre" (the default; deferred, LocalSystem, right after RemoveExistingProducts): after an
# installed package has been removed (install, upgrade), or at the start of an uninstall, before the
# services are stopped and the files are removed (this includes the nested uninstall of this package
# during a later upgrade).
# 1. Stops services only for the actual Server/Shared install or removal actions supplied after
#    MSI CostFinalize, whoever registered them (this package, an older package, ZIP or in-box).
# 2. Ends leftover OpenSSH processes that would keep files locked: server processes running from
#    this package's folder, the in-box folder or the folder of the registered sshd service, and
#    client tools running from this package's folder. Other OpenSSH builds (Cygwin, MSYS2, Git)
#    are left alone. The process tree that hosts this installation (an administrator running
#    msiexec inside an SSH session) is kept. Client-only changes preserve server services and
#    processes; retained features have action none and are left alone.
# 3. On Server install, upgrade and repair (not uninstall or feature removal): removes the in-box
#    "OpenSSH Server" Windows capability (KEEP_INBOX_OPENSSH=1 skips this) and re-applies the
#    sshd.exe process mitigation that the removal deletes. When Windows finishes that removal
#    only at the next restart, a one-time startup task re-applies the mitigation after that
#    restart and deletes itself.
# 4. On Server removal: deletes that startup task if it has not run yet.
#
# Phase "sessions" (immediate, before InstallValidate, only with ACTIVE_SESSIONS=abort): exits 1,
# which stops the installation before anything has changed, when step 2 above would end an SSH
# session (an sshd-session.exe process that does not host this installation).
#
# The sshd firewall rule belongs to the package: removing the old package deletes it, and the new
# package creates it again with port 22. The services are registered again as Automatic and
# started. These phases carry the settings over an install, upgrade or repair of the server or the
# agent, in HKLM\SOFTWARE\OpenSSH\Installer (only SYSTEM and Administrators can write there):
# - "fwsave" (deferred, LocalSystem; InstallExecute runs it before RemoveExistingProducts removes the
#   old package): writes value Services: which of sshd and ssh-agent are running, and the start type
#   to keep, Disabled or Automatic (Delayed Start), of a service registered from this package's
#   folder (not of the in-box registration: its defaults are Windows', not an administrator's).
#   With the Server feature, when a package of this series is installed (-Previous keep), writes
#   value FirewallRule: the rule's LocalPorts, Profiles, Enabled and RemoteAddresses. The rule of
#   OpenSSH Server PN Manager counts when the package's rule is missing. Otherwise only removes a
#   leftover firewall record.
# - "firewall" (deferred, after the WiX firewall action has created the rule): sets the rule.
#   Networks: FIREWALL_PROFILES, else the saved ones, else all on Windows Server and Domain plus
#   Private on client editions. Ports: SSHD_PORT, else the saved ones, else 22 (server.wxs). Enabled
#   and remote addresses: the saved ones, else enabled and any.
# - "svcrestore" (deferred, after StartServices and phase "port"): sets the kept start types again
#   and stops a service that is Disabled again.
# - "fwcommit" (commit): deletes the record once the installation has succeeded.
# - "fwrollback" (rollback, the last step of a rollback): when the installation fails, puts the
#   saved settings back on the rule that the rolled-back old package re-created, sets the kept start
#   types again, starts the services that were running and deletes the record. Phase "pre" stops
#   them before Windows Installer's StopServices, whose rollback therefore does not start them.
#
# Phase "port" (deferred, after StartServices, only with SSHD_PORT): sets "Port <n>" in
# %ProgramData%\ssh\sshd_config (the previous file is kept as sshd_config.bak.<date>-<time>, named in
# value SshdConfig) and restarts sshd. If then not the sshd service alone listens on the port (it
# could not bind, or another program holds the port), the previous file is put back, sshd is
# restarted and the firewall rule gets the port(s) of that file. Phase "portrollback" (rollback)
# puts the previous file back when the installation fails, or deletes sshd_config when phase
# "port" created it.
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
    [string]$Previous = '',
    [string]$ServerAction = 'none',
    [string]$ClientAction = 'none',
    [string]$SharedAction = 'none'
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
# Resolved actions come from MSI after CostFinalize. REMOVE alone cannot distinguish a full
# install from ADDLOCAL=Client, or a client-only uninstall from removal of the server.
$featureRemoval = ($Remove -ne '' -and -not $uninstall)
$touchServer = @('install', 'remove') -contains $ServerAction
$touchClient = @('install', 'remove') -contains $ClientAction
$touchShared = @('install', 'remove') -contains $SharedAction
# 32-bit PowerShell reaches the native System32 through Sysnative. The x86 package starts the
# 32-bit PowerShell (WixQuietExec), also on 64-bit Windows; the x64 and ARM64 packages start the
# native one (WixQuietExec64).
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
$altRuleName = 'OpenSSH SSH Server (sshd)'        # OpenSSH Server PN Manager creates this one when the rule above is missing
$recordKey = 'HKLM\SOFTWARE\OpenSSH\Installer'
$recordValue = 'FirewallRule'
$serviceValue = 'Services'
$portValue = 'SshdConfig'
$sc = Join-Path $sysNative 'sc.exe'
# First lines of the sections that OpenSSH Server PN Manager keeps in sshd_config before its Match blocks
# (Auth.cs and Sftp.cs, RegionBegin), and that of its earlier name, OpenSSH Server Manager (1.6.0 and older).
$managerRegions = @(
    '# Login methods by user and group, managed on the Authentication tab of OpenSSH Server Manager.',
    '# Login methods by user and group, managed on the Authentication tab of OpenSSH Server PN Manager.',
    '# SFTP-only accounts, managed on the SFTP tab of OpenSSH Server PN Manager.')
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

# The settings of the sshd rule as a record hashtable, or $null. The rule of OpenSSH Server PN Manager
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

function Get-SavedRecord([string]$value = $recordValue) {
    $out = & $reg query $recordKey /v $value 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { return '' }
    foreach ($line in ($out -split "`r?`n")) { if ($line -match ('^\s*' + $value + '\s+REG_SZ\s+(.*?)\s*$')) { return $matches[1] } }
    return ''
}

function Save-Record([string]$text, [string]$value = $recordValue) {
    & $reg add $recordKey /v $value /t REG_SZ /d $text /f 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# Deletes one value of the record; '' deletes the whole key (commit and rollback, which end the
# installation that wrote it).
function Remove-Record([string]$value = $recordValue) {
    if ($value -eq '') { & $reg delete $recordKey /f 2>&1 | Out-Null } else { & $reg delete $recordKey /v $value /f 2>&1 | Out-Null }
}

# ---- services ----

# The start type an upgrade or repair keeps, from the values Start and DelayedAutostart of the
# service: 'disabled', 'delayed-auto' (sc.exe names), or '' (Automatic and Manual come from the package).
function Get-KeptStart($start, $delayed) {
    if ([string]$start -eq '4') { return 'disabled' }
    if ([string]$start -eq '2' -and [string]$delayed -eq '1') { return 'delayed-auto' }
    return ''
}

# Running, Start, Delayed and Dir (the ImagePath without quotes and its last part: the folder of the
# binary when no argument has a backslash) of sshd and ssh-agent; a service that is not registered
# is left out.
function Get-ServiceStates {
    $states = @{}
    foreach ($name in @('sshd', 'ssh-agent')) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $k = Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $name) -ErrorAction SilentlyContinue
        $states[$name] = @{ Running = ($svc.Status -eq 'Running'); Start = $k.Start; Delayed = $k.DelayedAutostart; Dir = ([string]$k.ImagePath -replace '"|\\[^\\]*$', '') }
    }
    return $states
}

# The record is one line: v1|<name>=<1 running, 0 not>,<start type to keep>|... A start type is
# kept for a package's service, whatever its folder or architecture (an upgrade from x86, an
# INSTALLFOLDER not passed again), never for the in-box one in $inbox: its types are Windows' defaults.
function ConvertTo-ServiceRecord($states, [string]$inbox) {
    $text = 'v1'
    foreach ($name in @('sshd', 'ssh-agent')) {
        $s = $states[$name]
        if (-not $s) { continue }
        $keep = ''
        if ([string]$s.Dir -ne '' -and -not [string]::Equals([string]$s.Dir, $inbox, [StringComparison]::OrdinalIgnoreCase)) { $keep = Get-KeptStart $s.Start $s.Delayed }
        $run = '0'
        if ($s.Running) { $run = '1' }
        $text += '|' + $name + '=' + $run + ',' + $keep
    }
    return $text
}

# Name -> @{ Running; Start }; only the two service names and known start types are accepted.
function ConvertFrom-ServiceRecord([string]$text) {
    $r = @{}
    $parts = @($text.Trim() -split '\|')
    if ($parts[0] -ne 'v1') { return $r }
    foreach ($part in $parts) {
        if ($part -match '^(sshd|ssh-agent)=([01]),(disabled|delayed-auto)?$') { $r[$matches[1]] = @{ Running = ($matches[2] -eq '1'); Start = [string]$matches[3] } }
    }
    return $r
}

# What phases svcrestore and fwrollback do, for the saved record and the current states: 'config
# <name> <start type>' when the re-registration replaced the kept start type, 'stop <name>' for a
# running service that is Disabled again and, with $rollback, 'start <name>' for a service that ran
# before and is stopped now.
function Get-ServicePlan($saved, $states, [bool]$rollback) {
    $plan = @()
    foreach ($name in @('sshd', 'ssh-agent')) {
        $r = $saved[$name]
        $s = $states[$name]
        if (-not $r -or -not $s) { continue }
        $start = $r.Start
        if ($start -ne '' -and (Get-KeptStart $s.Start $s.Delayed) -ne $start) {
            $plan += ('config ' + $name + ' ' + $start)
            if ($start -eq 'disabled' -and $s.Running) { $plan += ('stop ' + $name) }
        }
        if ($rollback -and $r.Running -and -not $s.Running -and $start -ne 'disabled') { $plan += ('start ' + $name) }
    }
    return $plan
}

# ---- sshd_config ----

# sshd_config text with "Port <port>", following OpenSSH Server PN Manager (SshdConfig.SetFirst): the
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
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*Match(\s|=|$)' -or $managerRegions -ccontains $lines[$i].Trim()) { $end = $i; break } }
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

# The ports named by top-level ListenAddress lines. An address without a port uses every Port
# value (22 if none); an explicit address:port uses only that port. Without ListenAddress, all
# Port values apply. Includes are not expanded by this text-only fallback.
function Get-SshdConfigPorts([string]$text) {
    $ports = @()
    $listen = @()
    $hasListen = $false
    $useGlobal = $false
    foreach ($l in ($text -split "`r?`n")) {
        if ($l -match '^\s*Match(\s|=|$)' -or $managerRegions -ccontains $l.Trim()) { break }
        if ($l -match '^\s*Port(?:\s*=\s*|\s+)([0-9]{1,5})\s*(#.*)?$') { $p = [string][int]$matches[1]; if ($ports -notcontains $p) { $ports += $p } }
        elseif ($l -match '^\s*ListenAddress(?:\s*=\s*|\s+)') {
            $hasListen = $true
            if ($l -match '^\s*ListenAddress(?:\s*=\s*|\s+)(?:\[[^\]]*\]|[^\s:#\[]+):([0-9]{1,5})(\s|#|$)') {
                $p = [string][int]$matches[1]; if ($listen -notcontains $p) { $listen += $p }
            } else { $useGlobal = $true }
        }
    }
    if ($ports.Count -eq 0) { $ports = @('22') }
    if (-not $hasListen) { return $ports }
    if ($useGlobal) { foreach ($p in $ports) { if ($listen -notcontains $p) { $listen += $p } } }
    return $listen
}

# sshd_config.bak.yyyyMMdd-HHmmss, with -2, -3 ... when a backup of that second exists already
# (the names OpenSSH Server PN Manager uses, so its Restore dialog lists them).
function Get-BackupPath([string]$path, [DateTime]$now) {
    $b = $path + '.bak.' + $now.ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)
    if (-not (Test-Path -LiteralPath $b)) { return $b }
    $i = 2
    while (Test-Path -LiteralPath ($b + '-' + $i)) { $i++ }
    return ($b + '-' + $i)
}

# A new file (it must not exist) with the owner, group and permissions of the security descriptor
# $sd (binary form), or only its permissions when the owner cannot be set (another account owns
# the original); the bytes are written once the permissions are in place. When a step fails, the
# file is deleted: an empty or partly written backup must not be taken for the previous file.
function New-SecuredFile([string]$file, [byte[]]$sd, [byte[]]$bytes) {
    (New-Object IO.FileStream($file, [IO.FileMode]::CreateNew)).Close()
    try {
        foreach ($s in @('Owner, Group, Access', 'Access')) {
            $fs = New-Object Security.AccessControl.FileSecurity
            $fs.SetSecurityDescriptorBinaryForm($sd, $s)
            try { [IO.File]::SetAccessControl($file, $fs); break } catch { if ($s -eq 'Access') { throw $_ } }
        }
        [IO.File]::WriteAllBytes($file, $bytes)
    } catch {
        $err = $_
        try { [IO.File]::Delete($file) } catch { }
        throw $err
    }
}

# Replaces the file as OpenSSH Server PN Manager does (ConfigurationTransaction.AtomicBytes): the
# bytes go to a temporary file in the same folder with the owner, group, permissions, attributes
# and creation time of the live file, and a rename (MoveFileEx, replacing an existing file, through
# Microsoft.VisualBasic in PowerShell 2.0) swaps it in. Unlike ReplaceFile, the rename does not turn
# inherited permission entries into explicit ones (seen on Windows Server 2022). $backup, unless
# '', becomes a copy of the previous file with the same permissions. Throws when a step fails; the
# live file is then unchanged.
function Write-ConfigBytes([string]$path, [byte[]]$bytes, [string]$backup) {
    $sd = [IO.File]::GetAccessControl($path, 'Owner, Group, Access').GetSecurityDescriptorBinaryForm()
    if ($backup -ne '') { New-SecuredFile $backup $sd ([IO.File]::ReadAllBytes($path)) }
    $tmp = $path + '.new-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    try {
        New-SecuredFile $tmp $sd $bytes
        [IO.File]::SetCreationTimeUtc($tmp, [IO.File]::GetCreationTimeUtc($path))
        [IO.File]::SetAttributes($tmp, [IO.File]::GetAttributes($path))
        Add-Type -AssemblyName Microsoft.VisualBasic
        [Microsoft.VisualBasic.FileIO.FileSystem]::MoveFile($tmp, $path, $true)
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# Writes text in the encoding of the file (UTF-8, its byte order mark kept or left out).
function Write-ConfigText([string]$path, [string]$text, [string]$backup) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $enc = New-Object Text.UTF8Encoding($bom)
    Write-ConfigBytes $path ([byte[]]($enc.GetPreamble() + $enc.GetBytes($text))) $backup
}

# The IDs of the processes listening on TCP port $port, from the output of "netstat -ano": the rows
# whose foreign address is 0.0.0.0:0 or [::]:0. The state column is localized and is not read.
function Get-PortListenerPids([string]$text, [int]$port) {
    $ids = @()
    foreach ($l in ($text -split "`r?`n")) {
        if ($l -match '^\s*TCP\s+\S+:([0-9]+)\s+(0\.0\.0\.0:0|\[::\]:0)\s.*\s([0-9]+)\s*$' -and [int]$matches[1] -eq $port -and $ids -notcontains [int]$matches[3]) { $ids += [int]$matches[3] }
    }
    return $ids
}

# True when the port has listeners and all of them are the sshd service process.
function Test-PortOwnedBySshd($ids, [int]$sshdPid) {
    $ids = @($ids)
    return ($sshdPid -gt 0 -and $ids.Count -gt 0 -and @($ids | Where-Object { $_ -ne $sshdPid }).Count -eq 0)
}

# The process ID of the sshd service when it alone listens on the port, else 0.
function Get-SshdOnPort([int]$port) {
    $id = 0
    if ((& $sc queryex sshd 2>&1 | Out-String) -match 'PID\s*:\s*([0-9]+)') { $id = [int]$matches[1] }
    if (Test-PortOwnedBySshd (Get-PortListenerPids (& (Join-Path $sysNative 'netstat.exe') -ano 2>&1 | Out-String) $port) $id) { return $id }
    return 0
}

# True when the sshd service alone listens on the port, the same process still after 3 more
# seconds (sshd stops by itself when it cannot bind any address, and keeps running when it binds
# only some: another program on the port then serves part of the connections).
function Test-SshdListening([int]$port) {
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        $id = Get-SshdOnPort $port
        if ($id -ne 0) {
            Start-Sleep -Seconds 3
            return ((Get-SshdOnPort $port) -eq $id)
        }
    }
    return $false
}

# Gives the firewall rule these ports; returns a sentence for the log, '' when that failed.
function Set-RulePorts([string]$ports) {
    try {
        $res = Set-RuleSettings (New-Object -ComObject HNetCfg.FwPolicy2) $ruleName @{ LocalPorts = $ports }
        if ($res['Rules'] -gt 0 -and $res['Errors'].Count -eq 0) { return (' The firewall rule allows port ' + $ports + ' again.') }
    } catch { }
    return ''
}
#endregion firewall

if ($Phase -eq 'functions') { return }   # tests\preinstall.Tests.ps1 dot-sources the functions

#region firewall
# Runs a plan of Get-ServicePlan; the steps are logged, a failed one as a warning.
function Invoke-ServicePlan($plan, [string]$prefix) {
    foreach ($step in $plan) {
        $w = $step -split ' '
        try {
            switch ($w[0]) {
                'config' {
                    & $sc config $w[1] start= $w[2] 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw ('sc.exe exit ' + $LASTEXITCODE) }
                    Log ($prefix + 'service ' + $w[1] + ': start type ' + $w[2] + ', as before')
                }
                'stop' { Stop-Service -Name $w[1] -Force -ErrorAction Stop; Log ($prefix + 'stopped ' + $w[1] + ' (disabled)') }
                'start' { Start-Service -Name $w[1] -ErrorAction Stop; Log ($prefix + 'started ' + $w[1]) }
            }
        } catch { Log ('warning: ' + $prefix + $step + ': ' + $_.Exception.Message) }
    }
}

if ($Phase -eq 'fwsave') {
    # Every value comes from this installation: a record left by an interrupted one is replaced.
    Remove-Record $portValue
    try {
        $services = ConvertTo-ServiceRecord (Get-ServiceStates) $inboxFolder
        if (-not (Save-Record $services $serviceValue)) { throw ('reg.exe exit ' + $LASTEXITCODE) }
        Log ("saved the services (<name>=<running>,<start type to keep>): " + $services)
    } catch { Remove-Record $serviceValue; Log ("warning: could not save the state of the services: " + $_.Exception.Message) }
    $old = Get-SavedRecord
    if ($Previous -ne 'keep' -or $ServerAction -ne 'install') {
        if ($old -ne '') { Remove-Record; Log ("removed a saved firewall record left by an interrupted installation: " + $old) }
        if ($ServerAction -eq 'install') { Log "fresh install: the firewall rule gets this package's defaults" }
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
    if ((Get-SavedRecord) -ne '') { Log "installation complete: removed the saved firewall settings" }
    Remove-Record ''
    exit 0
}

if ($Phase -eq 'svcrestore') {
    Invoke-ServicePlan (Get-ServicePlan (ConvertFrom-ServiceRecord (Get-SavedRecord $serviceValue)) (Get-ServiceStates) $false) ''
    exit 0
}

if ($Phase -eq 'fwrollback') {
    $saved = ConvertFrom-FirewallRecord (Get-SavedRecord)
    if ($saved -and $saved['Rule'] -eq $ruleName) {
        try {
            $res = Set-RuleSettings (New-Object -ComObject HNetCfg.FwPolicy2) $ruleName $saved
            foreach ($e in $res['Errors']) { Log ("warning: rollback: could not set " + $e) }
            if ($res['Rules'] -gt 0) { Log ("rollback: firewall rule '" + $ruleName + "' set back to " + (Format-FirewallRecord $saved)) }
            else { Log ("warning: rollback: firewall rule '" + $ruleName + "' not found; saved settings: " + (Format-FirewallRecord $saved)) }
        } catch { Log ("warning: rollback: could not set the firewall rule: " + $_.Exception.Message) }
    }
    # After the firewall rule: the rolled-back services run again as before the installation.
    Invoke-ServicePlan (Get-ServicePlan (ConvertFrom-ServiceRecord (Get-SavedRecord $serviceValue)) (Get-ServiceStates) $true) 'rollback: '
    Remove-Record ''
    exit 0
}

if ($Phase -eq 'portrollback') {
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    $b = Get-SavedRecord $portValue
    if ($b -eq 'created') {
        Remove-Item -LiteralPath $cfg -Force -ErrorAction Stop
        Log ("rollback: deleted " + $cfg + ", created by the SSHD_PORT step")
    } elseif ($b -match '^sshd_config\.bak\.[0-9]{8}-[0-9]{6}(-[0-9]+)?$') {
        Write-ConfigBytes $cfg ([IO.File]::ReadAllBytes((Join-Path $env:ProgramData ('ssh\' + $b)))) ''
        Log ("rollback: sshd_config put back from " + $b)
    }
    Remove-Record $portValue
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
    # Phase portrollback undoes what this phase changes: the record names it before the change.
    $created = -not (Test-Path -LiteralPath $cfg)
    if ($created) {
        $null = Save-Record 'created' $portValue
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
        if (-not $created) { $null = Save-Record (Split-Path -Leaf $backup) $portValue }
        try { Write-ConfigText $cfg $new $backup } catch {
            # sshd_config is unchanged: nothing for phase portrollback to put back (the backup may be
            # incomplete). A file this step created stays recorded, for the rollback to delete it.
            if (-not $created) { Remove-Record $portValue }
            # The firewall step has already given the rule the new port: back to the port(s) sshd keeps using.
            $ports = @(Get-SshdConfigPorts $text) -join ','
            Log ("warning: sshd_config unchanged, sshd keeps port " + $ports + ": " + $_.Exception.Message + (Set-RulePorts $ports))
            exit 0
        }
        Log ("sshd_config: Port " + $port + " (previous file: " + $backup + ")")
    }
    $others = @(Get-SshdConfigPorts $new | Where-Object { $_ -ne [string]$port })
    if ($others.Count -gt 0) { Log ("sshd_config has further Port lines; sshd also listens on " + ($others -join ', ')) }
    try { Restart-Service -Name sshd -Force -ErrorAction Stop } catch { Log ("warning: restarting sshd: " + $_.Exception.Message) }
    if (Test-SshdListening $port) { Log ("sshd restarted and listens on port " + $port); exit 0 }
    $why = "warning: the sshd service does not listen on port " + $port + " alone (port in use, or blocked by a ListenAddress line?). "
    if ($backup -eq '') { Log ($why + "Check the OpenSSH/Operational event log."); exit 0 }
    # Back to the previous configuration, so the server stays reachable as before. sshd is stopped
    # first: a service restarting after a failure could hold the file while the rename replaces it.
    try { Stop-Service -Name sshd -Force -ErrorAction Stop } catch { }
    try { Write-ConfigBytes $cfg ([IO.File]::ReadAllBytes($backup)) '' } catch {
        Log ($why + "Copy " + $backup + " over sshd_config and restart sshd; it could not be put back: " + $_.Exception.Message)
        exit 0
    }
    try { Restart-Service -Name sshd -Force -ErrorAction Stop } catch { }
    $ports = @(Get-SshdConfigPorts ([IO.File]::ReadAllText($cfg))) -join ','
    Log ($why + "The previous sshd_config is back and sshd was restarted with port " + $ports + "." + (Set-RulePorts $ports) + " Check the OpenSSH/Operational event log, then set the port with OpenSSH Server PN Manager.")
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
Log ("mode=" + $(if ($uninstall) { 'uninstall' } elseif ($featureRemoval) { 'feature removal (REMOVE=' + $Remove + ')' } else { 'install' }) + " folder='" + $folder + "' KEEP_INBOX_OPENSSH='" + $KeepInbox + "' user=" + [Security.Principal.WindowsIdentity]::GetCurrent().Name + " PowerShell " + $PSVersionTable.PSVersion)

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
# OpenSSH Server PN Manager (Server feature): only the runs of its scheduled tasks ("--agent watch" every minute, as
# SYSTEM), which would hold the file; a window an administrator has open is left alone.
$managerExe = 'OpenSSHServerPNManager.exe'
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
    $isAgent = ($name -eq $managerExe -and [string]$p.CommandLine -match '\s--agent\s')
    if ((-not $isServer -and -not $isClient -and -not $isShared -and -not $isAgent) -or $path -eq '') { continue }
    $dir = (Split-Path -Path $path -Parent).TrimEnd('\')
    $inFolder = ($folder -ne '' -and [string]::Equals($dir, $folder, [StringComparison]::OrdinalIgnoreCase))
    $target = $false
    if ($isServer -and $touchServer -and (Test-InDirs $dir $serverDirs)) { $target = $true }
    if ($isClient -and $touchClient -and $inFolder) { $target = $true }
    if ($isShared -and $touchShared -and $inFolder) { $target = $true }
    if ($isAgent -and $touchServer -and $inFolder) { $target = $true }
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
if ($ServerAction -eq 'install' -and (Test-Path -LiteralPath $inboxSshd)) {
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
if ($ServerAction -eq 'remove') { Remove-MitigationTask }

Log "done"
exit 0
#endregion pre

Log ("warning: phase '" + $Phase + "' is not part of this script; nothing done")
exit 0
