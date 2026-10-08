# Checks a built package without installing it:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File src\contrib\win32\install\tests\package.Tests.ps1 [-Msi <path>]
# Default: bin\x64\Release\openssh.msi next to openssh.wixproj. Exit code: the number of failed checks.
# The database is opened read-only. For the launch conditions, a Windows Installer session is
# opened on the package (Installer.OpenPackage, machine state ignored, no user interface); the
# test sets properties in that session and evaluates the conditions of the LaunchCondition table.
# No action runs and nothing is installed.
# - InstallExecuteSequence: the ACTIVE_SESSIONS check before InstallValidate; the firewall save step
#   (and its rollback) between InstallInitialize and InstallExecute, with RemoveExistingProducts
#   immediately after InstallExecute (ICE63, error 2613); the firewall step after the WiX action
#   that creates the rule, its commit after it; the SSHD_PORT step after StartServices.
# - CustomAction types (immediate / deferred / rollback / commit, no impersonation, return code).
# - The powershell.exe command lines: -InputFormat None (without it Windows PowerShell 2.0 waits for the end of the
#   standard input that WixQuietExec keeps open, and the installation hangs on Windows 7 and Server 2008 R2); every
#   CustomAction.Target within its 255 characters.
# - ServiceInstall: ErrorControl normal; SecureCustomProperties.
# - LaunchCondition: SSHD_PORT and ACTIVE_SESSIONS values accepted and refused.
param([string]$Msi = '')
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Msi -eq '') { $Msi = Join-Path (Split-Path -Parent $here) 'bin\x64\Release\openssh.msi' }
$Msi = (Resolve-Path -LiteralPath $Msi).Path

$script:failed = 0
$script:passed = 0
function Check([string]$name, $condition, [string]$detail = '') {
    if ($condition) { $script:passed++; Write-Output ("ok   " + $name) }
    else { $script:failed++; Write-Output ("FAIL " + $name + $(if ($detail) { ": " + $detail } else { '' })) }
}
function Invoke($o, [string]$m, $a) { return $o.GetType().InvokeMember($m, 'InvokeMethod', $null, $o, $a) }
function GetP($o, [string]$p, $a) { return $o.GetType().InvokeMember($p, 'GetProperty', $null, $o, $a) }
function SetP($o, [string]$p, $a) { $null = $o.GetType().InvokeMember($p, 'SetProperty', $null, $o, $a) }

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = Invoke $installer 'OpenDatabase' @($Msi, 0)   # msiOpenDatabaseModeReadOnly
function Rows([string]$sql) {
    $view = Invoke $db 'OpenView' @($sql)
    $null = Invoke $view 'Execute' $null
    $rows = New-Object System.Collections.ArrayList
    while ($true) {
        $r = Invoke $view 'Fetch' $null
        if (-not $r) { break }
        $n = GetP $r 'FieldCount' $null
        $cells = @()
        for ($i = 1; $i -le $n; $i++) { $cells += [string](GetP $r 'StringData' @($i)) }
        $null = $rows.Add($cells)
    }
    $null = Invoke $view 'Close' $null
    return , $rows
}

Write-Output ("package: " + $Msi)
$seq = @{}; $cond = @{}; $order = @()
foreach ($r in (Rows 'SELECT `Action`, `Sequence`, `Condition` FROM `InstallExecuteSequence` ORDER BY `Sequence`')) { $seq[$r[0]] = [int]$r[1]; $cond[$r[0]] = $r[2]; $order += $r[0] }
$type = @{}; $target = @{}
foreach ($r in (Rows 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')) { $type[$r[0]] = [int]$r[1]; $target[$r[0]] = $r[3] }
function Before([string]$a, [string]$b) { Check ($a + ' before ' + $b) ($seq.ContainsKey($a) -and $seq.ContainsKey($b) -and $seq[$a] -lt $seq[$b]) ([string]$seq[$a] + ' / ' + [string]$seq[$b]) }
function Between([string]$from, [string]$to) {
    $l = @(); $in = $false
    foreach ($a in $order) { if ($a -eq $to) { break }; if ($in) { $l += $a }; if ($a -eq $from) { $in = $true } }
    return $l
}

# ACTIVE_SESSIONS=abort: immediate, before anything changes
Before 'OpenSSHCheckSessions' 'InstallValidate'
Before 'SetOpenSSHCheckSessionsCommand' 'OpenSSHCheckSessions'
Check 'OpenSSHCheckSessions condition' ($cond['OpenSSHCheckSessions'] -match 'ACTIVE_SESSIONS ~= "abort"') $cond['OpenSSHCheckSessions']
Check 'OpenSSHCheckSessions: immediate (not in script), return code checked' (($type['OpenSSHCheckSessions'] -band 0x400) -eq 0 -and ($type['OpenSSHCheckSessions'] -band 0x40) -eq 0) ([string]$type['OpenSSHCheckSessions'])
Check 'the check runs the pre-install script with phase sessions and resolved feature actions' ($target['SetOpenSSHCheckSessionsCommand'] -match '\[PreInstallCommand\] .* sessions \[OpenSSHFeatureArguments\]"$') $target['SetOpenSSHCheckSessionsCommand']
Before 'CostFinalize' 'ResolveServerInstall'
Before 'ResolveSharedRemove' 'SetOpenSSHFeatureArguments'
Before 'SetOpenSSHFeatureArguments' 'SetOpenSSHCheckSessionsCommand'
Check 'server install action uses the selected feature action' ($cond['ResolveServerInstall'] -eq '&Server = 3')
Check 'server removal requires an installed server feature' ($cond['ResolveServerRemove'] -eq '&Server = 2 AND !Server = 3')
Check 'client install action uses the selected feature action' ($cond['ResolveClientInstall'] -eq '&Client = 3')
Check 'client removal requires an installed client feature' ($cond['ResolveClientRemove'] -eq '&Client = 2 AND !Client = 3')
Check 'shared service follows component installation' ($cond['ResolveSharedInstall'] -eq '$SshAgentComponent = 3')
Check 'shared service removal requires an installed component' ($cond['ResolveSharedRemove'] -eq '$SshAgentComponent = 2 AND ?SshAgentComponent = 3')
foreach ($name in @('Server', 'Client', 'Shared')) {
    Check ($name + ' action reaches the preinstall script') ($target['SetOpenSSHFeatureArguments'].Contains('-' + $name + "Action '[OpenSSH" + $name + "Action]'"))
}
Check 'deferred cleanup receives resolved feature actions' ($target['SetOpenSSHPreInstall'].Contains('[OpenSSHFeatureArguments]'))

# firewall save before the removal of the old package
Before 'InstallInitialize' 'OpenSSHFirewallSaveRollback'
Before 'OpenSSHFirewallSaveRollback' 'OpenSSHFirewallSave'
Before 'OpenSSHFirewallSave' 'InstallExecute'
$afterExecute = @(Between 'InstallExecute' 'InstallFinalize')
Check 'RemoveExistingProducts immediately after InstallExecute (ICE63)' ($afterExecute.Count -gt 0 -and $afterExecute[0] -eq 'RemoveExistingProducts') ($afterExecute[0])
$scripted = @(Between 'InstallInitialize' 'InstallExecute' | Where-Object { $type.ContainsKey($_) -and ($type[$_] -band 0x400) })
Check 'the only script actions before InstallExecute are the save step and its rollback' (($scripted -join ',') -eq 'OpenSSHFirewallSaveRollback,OpenSSHFirewallSave') ($scripted -join ',')
Before 'RemoveExistingProducts' 'OpenSSHPreInstall'
Before 'OpenSSHPreInstall' 'ProcessComponents'
Before 'RemoveExistingProducts' 'InstallFiles'

# the rule is set after it is created
$sched = 'WixSchedFirewallExceptionsInstall'
if ($seq.ContainsKey('WixSchedFirewallExceptionsInstall_A64')) {
    $sched = 'WixSchedFirewallExceptionsInstall_A64'
    Check 'ARM64: only the ARM64 WiX firewall actions' (-not $seq.ContainsKey('WixSchedFirewallExceptionsInstall') -and -not $seq.ContainsKey('WixSchedFirewallExceptionsUninstall')) (($order | Where-Object { $_ -like 'WixSchedFirewall*' }) -join ',')
}
Before $sched 'OpenSSHFirewallProfiles'
Before 'OpenSSHFirewallProfiles' 'OpenSSHFirewallCommit'
Before 'StartServices' 'OpenSSHSshdPort'
Before 'OpenSSHSshdPort' 'InstallFinalize'
Check 'OpenSSHSshdPort condition' ($cond['OpenSSHSshdPort'] -eq 'SSHD_PORT AND &Server = 3') $cond['OpenSSHSshdPort']
foreach ($a in @('OpenSSHFirewallSave', 'OpenSSHFirewallSaveRollback', 'OpenSSHFirewallProfiles', 'OpenSSHFirewallCommit')) { Check ($a + ' condition') ($cond[$a] -eq '&Server = 3') $cond[$a] }
Check 'the save step: keep when a package of this series is installed' ($cond['SetOpenSSHFirewallSaveKeep'] -match '^Installed OR OPENSSH_PREVIOUS_INSTALLED OR OPENSSH_NEWER_INSTALLED' -and $target['SetOpenSSHFirewallSaveKeep'] -match 'fwsave -Previous keep"$')
Check 'the save step: fresh otherwise' ($cond['SetOpenSSHFirewallSaveFresh'] -eq ('NOT (' + $cond['SetOpenSSHFirewallSaveKeep'] + ')') -and $target['SetOpenSSHFirewallSaveFresh'] -match 'fwsave -Previous none"$')

# custom action types: 0x400 in script, 0x800 no impersonation, 0x100 rollback, 0x200 commit, 0x40 ignore exit code
foreach ($a in @('OpenSSHPreInstall', 'OpenSSHFirewallSave', 'OpenSSHFirewallProfiles', 'OpenSSHSshdPort')) {
    Check ($a + ': deferred, no impersonation, exit code ignored') (($type[$a] -band 0xF40) -eq 0xC40) ([string]$type[$a])
}
Check 'OpenSSHFirewallSaveRollback: rollback, no impersonation' (($type['OpenSSHFirewallSaveRollback'] -band 0xF00) -eq 0xD00) ([string]$type['OpenSSHFirewallSaveRollback'])
Check 'OpenSSHFirewallCommit: commit, no impersonation' (($type['OpenSSHFirewallCommit'] -band 0xF00) -eq 0xE00) ([string]$type['OpenSSHFirewallCommit'])
foreach ($a in @('SetOpenSSHFirewallSaveKeep', 'SetOpenSSHFirewallSaveRollback', 'SetOpenSSHFirewallCommit', 'SetOpenSSHFirewallProfiles', 'SetOpenSSHSshdPort')) {
    Check ($a + ' uses the firewall script') ($target[$a] -match '"\[FirewallCommand\] ')
}
Check 'the firewall step gets SSHD_PORT' ($target['SetOpenSSHFirewallProfiles'] -match "-SshdPort '\[SSHD_PORT\]'")

# powershell.exe command lines
$psActions = @($target.Keys | Where-Object { $target[$_] -match 'powershell\.exe"' } | Sort-Object)
Check 'the eight command lines that start powershell.exe' (($psActions -join ',') -eq 'SetOpenSSHCheckSessionsCommand,SetOpenSSHFirewallCommit,SetOpenSSHFirewallProfiles,SetOpenSSHFirewallSaveFresh,SetOpenSSHFirewallSaveKeep,SetOpenSSHFirewallSaveRollback,SetOpenSSHPreInstall,SetOpenSSHSshdPort') ($psActions -join ',')
foreach ($a in $psActions) {
    Check ($a + ': -NoProfile -NonInteractive -InputFormat None -Command') ($target[$a] -match 'powershell\.exe" -NoProfile -NonInteractive -InputFormat None -Command "') $target[$a]
}
$long = @($target.Keys | Where-Object { $target[$_].Length -gt 255 } | ForEach-Object { $_ + ' (' + $target[$_].Length + ')' })
Check 'every CustomAction.Target within 255 characters' ($long.Count -eq 0) ($long -join ', ')

# services, secure properties
foreach ($r in (Rows 'SELECT `Name`, `ErrorControl` FROM `ServiceInstall`')) {
    Check ('ServiceInstall ' + $r[0] + ': ErrorControl normal, vital') (([int]$r[1] -band 0x8007) -eq 0x8001) $r[1]
}
$props = @{}
foreach ($r in (Rows 'SELECT `Property`, `Value` FROM `Property`')) { $props[$r[0]] = $r[1] }
$secure = @($props['SecureCustomProperties'] -split ';')
foreach ($p in @('SSHD_PORT', 'ACTIVE_SESSIONS', 'FIREWALL_PROFILES', 'KEEP_INBOX_OPENSSH', 'ALLOWDOWNGRADE')) { Check ($p + ' is a secure property') ($secure -contains $p) }
Check 'ACTIVE_SESSIONS defaults to close' ($props['ACTIVE_SESSIONS'] -eq 'close')

# OpenSSH Server PN Manager: files and shortcuts in the Server feature, the uninstall step, the wizard after installing
function LongName([string]$n) { $i = $n.IndexOf('|'); if ($i -ge 0) { return $n.Substring($i + 1) } return $n }
$fileComp = @{}
foreach ($r in (Rows 'SELECT `FileName`, `Component_` FROM `File`')) { $fileComp[(LongName $r[0])] = $r[1] }
$serverComps = @((Rows 'SELECT `Component_` FROM `FeatureComponents` WHERE `Feature_` = ''Server''') | ForEach-Object { $_[0] })
foreach ($f in @('OpenSSHServerPNManager.exe', 'OpenSSHServerPNManager.exe.config')) {
    Check ($f + ' is installed with the Server feature') ($fileComp.ContainsKey($f) -and $serverComps -contains $fileComp[$f])
}
$clientComps = @((Rows 'SELECT `Component_` FROM `FeatureComponents` WHERE `Feature_` = ''Client''') | ForEach-Object { $_[0] })
foreach ($f in @('OpenSSHServerPNManager.exe', 'OpenSSHServerPNManager.exe.config')) {
    Check ($f + ' is also installed with the Client feature') ($fileComp.ContainsKey($f) -and $clientComps -contains $fileComp[$f])
}
$shortcuts = @{}
foreach ($r in (Rows 'SELECT `Shortcut`, `Directory_`, `Name`, `Component_`, `Target`, `Arguments` FROM `Shortcut`')) { $shortcuts[$r[0]] = $r }
foreach ($s in @(@('ManagerShortcut', 'OpenSSH Server PN Manager', '--server'), @('WizardShortcut', 'OpenSSH Server PN setup wizard', '--wizard'))) {
    $r = $shortcuts[$s[0]]
    Check ('Start-menu shortcut "' + $s[1] + '"') ($r -and $r[1] -eq 'ProgramMenuFolder' -and (LongName $r[2]) -eq $s[1] -and $r[4] -eq '[INSTALLFOLDER]OpenSSHServerPNManager.exe' -and $r[5] -eq $s[2] -and $serverComps -contains $r[3]) $(if ($r) { $r -join ' | ' } else { 'missing' })
}
$clientShortcut = $shortcuts['ClientManagerShortcut']
Check 'client workspace shortcut is present with Client' ($clientShortcut -and $clientShortcut[5] -eq '--client' -and $clientComps -contains $clientShortcut[3])
$keyPath = @(Rows 'SELECT `Root`, `Key`, `Name` FROM `Registry`, `Component` WHERE `Component`.`KeyPath` = `Registry`.`Registry` AND `Component`.`Component` = ''ManagerShortcuts''')
Check 'the shortcuts: a per-machine registry key path (HKMU, root -1)' ($keyPath.Count -eq 1 -and $keyPath[0][0] -eq '-1') $(if ($keyPath.Count) { $keyPath[0] -join ' ' })
Before 'OpenSSHManagerUninstall' 'OpenSSHPreInstall'
Before 'OpenSSHManagerUninstall' 'RemoveFiles'
Before 'RemoveExistingProducts' 'OpenSSHManagerUninstall'
Check 'OpenSSHManagerUninstall: deferred, no impersonation, exit code ignored' (($type['OpenSSHManagerUninstall'] -band 0xF40) -eq 0xC40) ([string]$type['OpenSSHManagerUninstall'])
Check 'OpenSSHManagerUninstall: only when the Server feature is removed, not by an upgrade' ($cond['OpenSSHManagerUninstall'] -eq 'OpenSSHServerAction = "remove" AND NOT UPGRADINGPRODUCTCODE AND NETFX45_RELEASE') $cond['OpenSSHManagerUninstall']
Check 'OpenSSHManagerUninstall runs the manager from the install folder' ($target['SetOpenSSHManagerUninstall'] -eq '"[INSTALLFOLDER]OpenSSHServerPNManager.exe" --agent uninstall') $target['SetOpenSSHManagerUninstall']
Before 'InstallFiles' 'OpenSSHWizardRequest'
Before 'OpenSSHWizardRequest' 'InstallFinalize'
Check 'OpenSSHWizardRequest: deferred, no impersonation, exit code ignored' (($type['OpenSSHWizardRequest'] -band 0xF40) -eq 0xC40) ([string]$type['OpenSSHWizardRequest'])
Check 'OpenSSHWizardRequest runs the manager from the install folder' ($target['SetOpenSSHWizardRequest'] -eq '"[INSTALLFOLDER]OpenSSHServerPNManager.exe" --agent open-wizard') $target['SetOpenSSHWizardRequest']
Check 'OpenSSHWizardRequest: the condition of the step that starts the manager' ($cond['OpenSSHWizardRequest'] -eq $cond['OpenSSHOpenWizard']) $cond['OpenSSHWizardRequest']
Before 'InstallFinalize' 'OpenSSHOpenWizard'
Check 'OpenSSHOpenWizard: installed executable, asynchronous, as the user' ($type['OpenSSHOpenWizard'] -eq 210) ([string]$type['OpenSSHOpenWizard'])
Check 'OpenSSHOpenWizard explicitly requests the wizard' ($target['OpenSSHOpenWizard'] -eq '--wizard') $target['OpenSSHOpenWizard']
Check 'OPEN_WIZARD defaults to 1 and is a secure property' ($props['OPEN_WIZARD'] -eq '1' -and $secure -contains 'OPEN_WIZARD')
Before 'FindRelatedProducts' 'SetOpenSSHFirstInstall'
Check 'a first installation: the condition of the fresh firewall step' ($cond['SetOpenSSHFirstInstall'] -eq $cond['SetOpenSSHFirewallSaveFresh']) $cond['SetOpenSSHFirstInstall']

# launch conditions, evaluated by Windows Installer
$launch = Rows 'SELECT `Condition`, `Description` FROM `LaunchCondition`'
$portCond = ($launch | Where-Object { $_[1] -like 'SSHD_PORT*' } | Select-Object -First 1)
$sessCond = ($launch | Where-Object { $_[1] -like 'ACTIVE_SESSIONS*' } | Select-Object -First 1)
Check 'SSHD_PORT launch condition present' ($portCond -ne $null)
Check 'ACTIVE_SESSIONS launch condition present' ($sessCond -ne $null)
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
$db = $null
SetP $installer 'UILevel' @(2)   # msiUILevelNone
$session = Invoke $installer 'OpenPackage' @($Msi, 1)   # msiOpenPackageFlagsIgnoreMachineState
function Eval([string]$property, [string]$value, [string]$condition) {
    SetP $session 'Property' @($property, $value)
    return [int](Invoke $session 'EvaluateCondition' @($condition))   # 0 false, 1 true
}
foreach ($c in @(@('', 1), @('22', 1), @('1', 1), @('2222', 1), @('65535', 1), @('0022', 1), @('000000022', 1),
                 @('0', 0), @('65536', 0), @('-1', 0), @('100000', 0), @('abc', 0), @("22'", 0), @('22 2', 0), @('2e3', 0), @('0x16', 0), @('22;', 0), @("22' ; calc ; '", 0), @('99999999999', 0), @('+22', 0), @(' 22', 0), @('22 ', 0))) {
    $got = Eval 'SSHD_PORT' $c[0] $portCond[0]
    Check ("SSHD_PORT='" + $c[0] + "' " + $(if ($c[1] -eq 1) { 'accepted' } else { 'refused' })) ($got -eq $c[1]) ('EvaluateCondition=' + $got)
}
foreach ($c in @(@('', 1), @('close', 1), @('abort', 1), @('ABORT', 1), @('Close', 1), @('stop', 0), @('abort ', 0), @("abort'", 0), @('1', 0))) {
    $got = Eval 'ACTIVE_SESSIONS' $c[0] $sessCond[0]
    Check ("ACTIVE_SESSIONS='" + $c[0] + "' " + $(if ($c[1] -eq 1) { 'accepted' } else { 'refused' })) ($got -eq $c[1]) ('EvaluateCondition=' + $got)
}
# The check itself only runs for abort, whatever the case.
SetP $session 'Property' @('OpenSSHServerAction', 'install')
SetP $session 'Property' @('ACTIVE_SESSIONS', 'Abort')
Check 'OpenSSHCheckSessions condition true for ACTIVE_SESSIONS=Abort on a first install' ([int](Invoke $session 'EvaluateCondition' @($cond['OpenSSHCheckSessions'])) -eq 1)
SetP $session 'Property' @('OpenSSHServerAction', 'none')
Check 'Client-only install never runs the server session abort check' ([int](Invoke $session 'EvaluateCondition' @($cond['OpenSSHCheckSessions'])) -eq 0)
SetP $session 'Property' @('OpenSSHServerAction', 'install')
SetP $session 'Property' @('ACTIVE_SESSIONS', 'close')
Check 'OpenSSHCheckSessions condition false for close' ([int](Invoke $session 'EvaluateCondition' @($cond['OpenSSHCheckSessions'])) -eq 0)
# The wizard after installing; the feature state is not costed in this session, so "&Server = 3" counts as true.
$wizardCond = $cond['OpenSSHOpenWizard'].Replace('&Server = 3', '1')
Check 'OpenSSHOpenWizard condition names the Server feature' ($cond['OpenSSHOpenWizard'] -match '&Server = 3') $cond['OpenSSHOpenWizard']
foreach ($c in @(@('first install, full window', '1', '5', '#528040', '1', 1), @('reduced window (/qr)', '1', '4', '#528040', '1', 1),
                 @('/passive or /qb', '1', '3', '#528040', '1', 0), @('/quiet', '1', '2', '#528040', '1', 0), @('OPEN_WIZARD=0', '0', '5', '#528040', '1', 0),
                 @('no .NET Framework 4.5', '1', '5', '', '1', 0), @('an upgrade or a repair', '1', '5', '#528040', '', 0))) {
    SetP $session 'Property' @('OPEN_WIZARD', $c[1]); SetP $session 'Property' @('UILevel', $c[2])
    SetP $session 'Property' @('NETFX45_RELEASE', $c[3]); SetP $session 'Property' @('OpenSSHFirstInstall', $c[4])
    $got = [int](Invoke $session 'EvaluateCondition' @($wizardCond))
    Check ('the wizard opens: ' + $c[0] + ' -> ' + $(if ($c[5] -eq 1) { 'yes' } else { 'no' })) ($got -eq $c[5]) ('EvaluateCondition=' + $got)
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($session) | Out-Null

Write-Output ''
Write-Output ("passed " + $script:passed + ", failed " + $script:failed)
exit $script:failed
