# Tests for ..\preinstall.ps1 that need neither administrator rights nor an installation.
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File src\contrib\win32\install\tests\preinstall.Tests.ps1
# Exit code: the number of failed checks. Written for Windows PowerShell 2.0 and later, like the
# script it tests. It dot-sources preinstall.ps1 with -Phase functions, which defines the functions
# and returns before any phase runs.
# - static: the script parses, uses no PowerShell 3+ syntax the tests know of, and the two scripts
#   that openssh.wixproj embeds (see there) keep every statement of their regions and fit on the
#   powershell.exe command line; when a build has written obj\<platform>\Release\preinstall.wxi,
#   its content is compared with the scripts made here.
# - pure functions: firewall record (de)serialisation, FIREWALL_PROFILES and SSHD_PORT parsing,
#   sshd_config Port editing, backup names, the process-tree logic of ACTIVE_SESSIONS=abort.
# - files: sshd_config is written through ReplaceFile in a temporary folder; the permissions of the
#   file and a UTF-8 BOM are kept.
# - read-only, on this machine: the sshd firewall rule is read through HNetCfg.FwPolicy2 and
#   serialised; reg.exe output is parsed from an existing HKLM value. Nothing is written outside
#   the temporary folder.
param([string]$Script = '')
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Script -eq '') { $Script = Join-Path (Split-Path -Parent $here) 'preinstall.ps1' }
$srcRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here)))   # ...\src

$script:failed = 0
$script:passed = 0
function Check([string]$name, $condition, [string]$detail = '') {
    if ($condition) { $script:passed++; Write-Output ("ok   " + $name) }
    else { $script:failed++; Write-Output ("FAIL " + $name + $(if ($detail) { ": " + $detail } else { '' })) }
}
function Same([string]$name, $expected, $actual) {
    $e = [string]$expected; $a = [string]$actual
    Check $name ($e -ceq $a) ("expected [" + $e + "] got [" + $a + "]")
}
function Show([string]$s) { return ($s -replace "`r", '\r' -replace "`n", '\n') }

# ---------------------------------------------------------------- static checks
$lines = [IO.File]::ReadAllLines($Script)
$text = [IO.File]::ReadAllText($Script)
$parseErrors = $null
$null = [System.Management.Automation.PSParser]::Tokenize($text, [ref]$parseErrors)
Check 'preinstall.ps1 tokenizes without errors (PSParser, PowerShell 2.0 API)' ($parseErrors.Count -eq 0) (($parseErrors | ForEach-Object { $_.Message }) -join '; ')
if ('System.Management.Automation.Language.Parser' -as [type]) {
    $t = $null; $e = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$t, [ref]$e)
    Check 'preinstall.ps1 parses without errors (Language.Parser.ParseFile)' ($e.Count -eq 0) (($e | ForEach-Object { 'line ' + $_.Extent.StartLineNumber + ': ' + $_.Message }) -join '; ')
}

# PowerShell 3+ constructs, looked for in the code only (comments and strings are left out).
$tokens = [System.Management.Automation.PSParser]::Tokenize($text, [ref]$parseErrors)
$ps3 = @()
for ($i = 0; $i -lt $tokens.Count; $i++) {
    $tk = $tokens[$i]; $c = [string]$tk.Content; $ty = [string]$tk.Type
    if ($ty -eq 'Operator' -and @('-in', '-notin', '-shl', '-shr') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'Type' -and @('ordered', 'pscustomobject') -contains $c.ToLower()) { $ps3 += ('[' + $c + '] (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'Member' -and @('new', 'where', 'foreach', 'isnullorwhitespace') -contains $c.ToLower()) { $ps3 += ('.' + $c + ' (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'Command' -and @('get-ciminstance', 'invoke-cimmethod', 'get-netfirewallrule', 'set-netfirewallrule', 'new-netfirewallrule', 'get-nettcpconnection', 'convertto-json', 'convertfrom-json', 'invoke-webrequest', 'invoke-restmethod', 'get-filehash') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'CommandParameter' -and @('-raw', '-nonewline') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'Variable' -and $c.ToLower() -eq 'psitem') { $ps3 += ('$PSItem (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'CommandArgument' -and $c -eq 'Ignore' -and $i -gt 0 -and [string]$tokens[$i - 1].Content -match '^-(ErrorAction|EA|WarningAction|WA)$') { $ps3 += ('-ErrorAction Ignore (line ' + $tk.StartLine + ')') }
    if ($ty -eq 'Keyword' -and @('class', 'enum', 'using', 'workflow') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
}
Check 'no PowerShell 3+ syntax, cmdlets or parameters known to the lint' ($ps3.Count -eq 0) ($ps3 -join ', ')

# The two scripts that openssh.wixproj (EmbedInstallerScript) embeds: a region of the dropped name
# is left out; with -Strip, comment lines, blank lines and indentation too, lines end with LF.
function Get-Variant([string[]]$src, [string]$drop, [bool]$strip) {
    $sb = New-Object System.Text.StringBuilder
    $skip = $false
    foreach ($line in $src) {
        $t = $line.Trim()
        if ($t -match '^#(end)?region\s+(\w+)' -and $matches[2] -eq $drop) { $skip = -not $matches[1]; continue }
        if ($skip) { continue }
        if ($strip) {
            if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
            $null = $sb.Append($t).Append("`n")
        } else { $null = $sb.Append($line).Append("`n") }
    }
    return $sb.ToString()
}
function Get-CodeTokens([string]$code) {
    $errs = $null
    $l = @()
    foreach ($tk in [System.Management.Automation.PSParser]::Tokenize($code, [ref]$errs)) {
        if (@('Comment', 'NewLine', 'LineContinuation') -contains [string]$tk.Type) { continue }
        $l += ([string]$tk.Type + ':' + [string]$tk.Content)
    }
    if ($errs.Count -gt 0) { $l += ('PARSE ERROR: ' + (($errs | ForEach-Object { $_.Message }) -join '; ')) }
    return $l
}
$wxiPaths = @()
# Only a build made after the last change of the script or the project is compared: an older one is simply stale.
$installDir = Split-Path -Parent $here
$sourcesTime = @((Get-Item (Join-Path $installDir 'preinstall.ps1')).LastWriteTimeUtc, (Get-Item (Join-Path $installDir 'openssh.wixproj')).LastWriteTimeUtc) | Sort-Object | Select-Object -Last 1
foreach ($p in @('x64', 'x86', 'ARM64')) {
    $w = Join-Path $installDir ('obj\' + $p + '\Release\preinstall.wxi')
    if (-not (Test-Path -LiteralPath $w)) { continue }
    if ((Get-Item -LiteralPath $w).LastWriteTimeUtc -lt $sourcesTime) { Write-Host ('skip ' + $w + ': built before the last change of preinstall.ps1 or openssh.wixproj') ; continue }
    $wxiPaths += $w
}
foreach ($v in @(@('PreInstallScript', 'firewall', 'pre'), @('FirewallScript', 'pre', 'firewall'))) {
    $name = $v[0]; $drop = $v[1]; $kept = $v[2]
    $full = Get-Variant $lines $drop $false
    $stripped = Get-Variant $lines $drop $true
    $a = @(Get-CodeTokens $full); $b = @(Get-CodeTokens $stripped)
    $diff = -1
    for ($i = 0; $i -lt [Math]::Max($a.Count, $b.Count); $i++) { if ($i -ge $a.Count -or $i -ge $b.Count -or $a[$i] -cne $b[$i]) { $diff = $i; break } }
    Check ($name + ': the embedded script keeps every token of the file (' + $b.Count + ' tokens)') ($diff -lt 0) ("first difference at token " + $diff)
    $b64 = [Convert]::ToBase64String((New-Object Text.UTF8Encoding($false)).GetBytes($stripped))
    Check ($name + ': ' + $b64.Length + ' characters of base64, within the 31000 of the build check') ($b64.Length -le 31000)
    Check ($name + ': no line starts with #') (-not ($stripped -match "(^|`n)#"))
    Check ($name + ': region ' + $drop + ' is left out') (-not ($stripped -match ('#region ' + $drop)))
    foreach ($wxiPath in $wxiPaths) {
        $m = [regex]::Match([IO.File]::ReadAllText($wxiPath), '<\?define ' + $name + '="([A-Za-z0-9+/=]+)"\?>')
        Check ($name + ': matches the script in ' + $wxiPath) ($m.Success -and $m.Groups[1].Value -ceq $b64) 'rebuild the package, or the embedding in openssh.wixproj and this test differ'
    }
}
$pre = Get-Variant $lines 'firewall' $true
$fw = Get-Variant $lines 'pre' $true
Check 'the pre-install script has no firewall phase' (-not ($pre -match "Phase -eq 'fwsave'") -and -not ($pre -match 'function Set-SshdConfigPortText'))
Check 'the firewall script has no process cleanup' (-not ($fw -match 'Stop-Process') -and -not ($fw -match 'function Get-KeepSet') -and -not ($fw -match 'Remove-Capability'))
Check 'the firewall script cannot fall through to phase pre' ($fw.TrimEnd() -match "is not part of this script; nothing done`"\)`nexit 0$")

# ---------------------------------------------------------------- load the functions
. $Script -Phase functions
Check 'dot-sourcing with -Phase functions defines the functions' ((Get-Command Set-SshdConfigPortText -ErrorAction SilentlyContinue) -ne $null)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- FIREWALL_PROFILES, SSHD_PORT
Same 'Get-ProfileMask empty' 0 (Get-ProfileMask '')
Same 'Get-ProfileMask all' (0x7FFFFFFF) (Get-ProfileMask 'all')
Same 'Get-ProfileMask domain,private' 3 (Get-ProfileMask 'domain,private')
Same 'Get-ProfileMask Domain' 1 (Get-ProfileMask 'Domain')
Same 'Get-ProfileMask private' 2 (Get-ProfileMask 'private')
Same 'Get-ProfileMask public' 4 (Get-ProfileMask 'public')
Same 'Get-ProfileText 3' 'Domain, Private (0x3)' (Get-ProfileText 3)
Same 'Get-ProfileText all' 'all networks (0x7FFFFFFF)' (Get-ProfileText 0x7FFFFFFF)
foreach ($c in @(@('22', 22), @('2222', 2222), @('65535', 65535), @('1', 1), @(' 2222 ', 2222), @('0022', 22), @('000000022', 22), @('0', 0), @('65536', 0), @('-1', 0), @('+22', 0), @('22a', 0), @('0x16', 0), ("22'", 0), @('', 0), @('2 2', 0), @('9999999999', 0))) {
    Same ("ConvertTo-Port '" + $c[0] + "'") $c[1] (ConvertTo-Port $c[0])
}

# ---------------------------------------------------------------- firewall record
$rec = @{ Rule = $ruleName; LocalPorts = '2222,2200-2210'; Profiles = 3; Enabled = $false; RemoteAddresses = '10.0.0.0/255.0.0.0,LocalSubnet,fe80::/64' }
$line = ConvertTo-FirewallRecord $rec
Same 'record text' 'v1|Rule=OpenSSH SSH Server Preview (sshd)|LocalPorts=2222,2200-2210|Profiles=3|Enabled=0|RemoteAddresses=10.0.0.0/255.0.0.0,LocalSubnet,fe80::/64' $line
$back = ConvertFrom-FirewallRecord $line
Check 'record round trip: all fields' ($back -ne $null -and $back.Count -eq 5)
foreach ($k in @('Rule', 'LocalPorts', 'Profiles', 'Enabled', 'RemoteAddresses')) { Same ('record round trip: ' + $k) $rec[$k] $back[$k] }
Same 'record: Enabled=1' $true (ConvertFrom-FirewallRecord ('v1|Rule=' + $ruleName + '|Enabled=1'))['Enabled']
$alt = ConvertFrom-FirewallRecord ('v1|Rule=' + $altRuleName + '|LocalPorts=*|Profiles=2147483647|Enabled=1|RemoteAddresses=*')
Check 'record of the manager rule, ports * and all profiles' ($alt -ne $null -and $alt['Rule'] -eq $altRuleName -and $alt['LocalPorts'] -eq '*' -and $alt['Profiles'] -eq 0x7FFFFFFF)
Same 'format' 'ports 2222,2200-2210, networks Domain, Private (0x3), disabled, remote addresses 10.0.0.0/255.0.0.0,LocalSubnet,fe80::/64' (Format-FirewallRecord $back)
Check 'record: unknown rule name rejected' ((ConvertFrom-FirewallRecord 'v1|Rule=Evil|LocalPorts=22') -eq $null)
Check 'record: other version rejected' ((ConvertFrom-FirewallRecord ('v2|Rule=' + $ruleName)) -eq $null)
Check 'record: empty text rejected' ((ConvertFrom-FirewallRecord '') -eq $null)
Check 'record: garbage rejected' ((ConvertFrom-FirewallRecord 'hello world') -eq $null)
$bad = ConvertFrom-FirewallRecord ("v1|Rule=" + $ruleName + "|LocalPorts=22';calc;'|Profiles=0|Enabled=yes|RemoteAddresses=1.2.3.4 5.6.7.8")
Check 'record: invalid values dropped, rule kept' ($bad -ne $null -and $bad.Count -eq 1 -and $bad['Rule'] -eq $ruleName) (($bad.Keys | ForEach-Object { $_ }) -join ',')
Check 'record: profiles out of range dropped' (-not (ConvertFrom-FirewallRecord ('v1|Rule=' + $ruleName + '|Profiles=4294967295')).ContainsKey('Profiles'))
Check 'record: over-long ports dropped' (-not (ConvertFrom-FirewallRecord ('v1|Rule=' + $ruleName + '|LocalPorts=' + ('1' * 1001))).ContainsKey('LocalPorts'))

# ---------------------------------------------------------------- sshd_config Port
$default = Join-Path $srcRoot 'bin\x64\Release\sshd_config_default'
if (-not (Test-Path -LiteralPath $default)) { $default = Join-Path $srcRoot 'contrib\win32\openssh\sshd_config' }
if (Test-Path -LiteralPath $default) {
    $d = [IO.File]::ReadAllText($default)
    $n = Set-SshdConfigPortText $d 2222
    $dl = @($d -split "`r?`n"); $nl = @($n -split "`r?`n")
    $changed = @(); for ($i = 0; $i -lt $dl.Count; $i++) { if ($dl[$i] -cne $nl[$i]) { $changed += ($i.ToString() + ': ' + $dl[$i] + ' -> ' + $nl[$i]) } }
    Check ('sshd_config_default: only "#Port 22" changes, to "Port 2222" (' + (Split-Path -Leaf $default) + ')') ($dl.Count -eq $nl.Count -and $changed.Count -eq 1 -and $changed[0] -match '#Port 22 -> Port 2222$') ($changed -join ' | ')
    Check 'sshd_config_default: line endings kept' (($d.Contains("`r`n")) -eq ($n.Contains("`r`n")) -and (($n -split "`r`n").Count -eq ($d -split "`r`n").Count))
    Same 'sshd_config_default: applying twice changes nothing more' $n (Set-SshdConfigPortText $n 2222)
    Same 'sshd_config_default: ports after the edit' '2222' ((Get-SshdConfigPorts $n) -join ',')
    Same 'sshd_config_default: ports before the edit' '22' ((Get-SshdConfigPorts $d) -join ',')
} else { Check 'sshd_config_default found' $false $default }

$cases = @(
    @('active Port line, comment kept', "#Port 22`r`nPort 22   # old`r`nPasswordAuthentication yes`r`n", "#Port 22`r`nPort 2222 # old`r`nPasswordAuthentication yes`r`n"),
    @('lower case and =', "port=22`n", "Port 2222`n"),
    @('only the first of two Port lines', "Port 22`nPort 2200`n", "Port 2222`nPort 2200`n"),
    @('prose is not an example', "# Port forwarding is off`nAllowTcpForwarding no`n", "# Port forwarding is off`nAllowTcpForwarding no`nPort 2222`n"),
    @('before the Match block, with a blank line', "LogLevel INFO`nMatch Group administrators`n       Port 22`n", "LogLevel INFO`nPort 2222`n`nMatch Group administrators`n       Port 22`n"),
    @('a Port line inside Match is not the global one', "Match User x`nPort 22`n", "Port 2222`n`nMatch User x`nPort 22`n"),
    @('before the first Include', "LogLevel INFO`nInclude conf.d/*.conf`nMatch all`n", "LogLevel INFO`nPort 2222`nInclude conf.d/*.conf`nMatch all`n"),
    @('commented example before Match', "#Port 22`nMatch all`n#Port 23`n", "Port 2222`nMatch all`n#Port 23`n"),
    @('no final line break is kept', "#Port 22`nLogLevel INFO", "Port 2222`nLogLevel INFO"),
    @('appended at the end with a line break', "LogLevel INFO", "LogLevel INFO`nPort 2222`n"),
    @('empty file', "", "Port 2222`n"),
    @('before the rules section of OpenSSH Server Manager', ("LogLevel INFO`n" + $managerRegion + "`nMatch User x`n"), ("LogLevel INFO`nPort 2222`n`n" + $managerRegion + "`nMatch User x`n")),
    @('PortForwarding-like keyword is not Port', "PortX 1`n", "PortX 1`nPort 2222`n")
)
foreach ($c in $cases) {
    $got = Set-SshdConfigPortText $c[1] 2222
    Check ('Set-SshdConfigPortText: ' + $c[0]) ($got -ceq $c[2]) ('expected [' + (Show $c[2]) + '] got [' + (Show $got) + ']')
}
Same 'Get-SshdConfigPorts: several Port lines' '2222,2200' ((Get-SshdConfigPorts "Port 2222`nPort 2200`nPort 2222`n") -join ',')
Same 'Get-SshdConfigPorts: ListenAddress ports' '2022,2023' ((Get-SshdConfigPorts "ListenAddress 0.0.0.0:2022`nListenAddress [::1]:2023`nListenAddress ::1`n") -join ',')
Same 'Get-SshdConfigPorts: Port wins over ListenAddress' '2200' ((Get-SshdConfigPorts "ListenAddress 0.0.0.0:2022`nPort 2200`n") -join ',')
Same 'Get-SshdConfigPorts: inside Match ignored' '22' ((Get-SshdConfigPorts "Match all`nPort 2200`n") -join ',')

# ---------------------------------------------------------------- files: backup name, ReplaceFile, permissions
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('preinstall-tests-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $tmp
try {
    $cfg = Join-Path $tmp 'sshd_config'
    $now = New-Object DateTime(2026, 9, 26, 14, 5, 9)
    Same 'Get-BackupPath' ($cfg + '.bak.20260926-140509') (Get-BackupPath $cfg $now)
    [IO.File]::WriteAllText(($cfg + '.bak.20260926-140509'), 'x')
    Same 'Get-BackupPath: second backup in the same second' ($cfg + '.bak.20260926-140509-2') (Get-BackupPath $cfg $now)
    [IO.File]::WriteAllText(($cfg + '.bak.20260926-140509-2'), 'x')
    Same 'Get-BackupPath: third' ($cfg + '.bak.20260926-140509-3') (Get-BackupPath $cfg $now)

    # A protected DACL that differs from what the folder would give a new file: the current account
    # (full control) and Administrators (read), nothing inherited.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = 'D:P(A;;FA;;;' + $me + ')(A;;FR;;;BA)'
    $old = "#Port 22`r`nLogLevel INFO`r`n"
    [IO.File]::WriteAllText($cfg, $old, (New-Object Text.UTF8Encoding($false)))
    $fs = New-Object Security.AccessControl.FileSecurity
    $fs.SetSecurityDescriptorSddlForm($sddl, 'Access')
    [IO.File]::SetAccessControl($cfg, $fs)
    $before = [IO.File]::GetAccessControl($cfg).GetSecurityDescriptorSddlForm('Access')
    $backup = Get-BackupPath $cfg (Get-Date)
    $how = Write-ConfigText $cfg (Set-SshdConfigPortText $old 2222) $backup
    Same 'Write-ConfigText: written through ReplaceFile' 'replaced' $how
    Same 'Write-ConfigText: new content' "Port 2222`r`nLogLevel INFO`r`n" ([IO.File]::ReadAllText($cfg))
    Same 'Write-ConfigText: backup holds the previous content' $old ([IO.File]::ReadAllText($backup))
    Same 'Write-ConfigText: sshd_config keeps its permissions' $before ([IO.File]::GetAccessControl($cfg).GetSecurityDescriptorSddlForm('Access'))
    Same 'Write-ConfigText: the backup keeps them too' $before ([IO.File]::GetAccessControl($backup).GetSecurityDescriptorSddlForm('Access'))
    $bytes = [IO.File]::ReadAllBytes($cfg)
    Check 'Write-ConfigText: no BOM added' (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB))
    Check 'Write-ConfigText: no temporary file left' (@(Get-ChildItem -LiteralPath $tmp -Filter 'sshd_config.new-*').Count -eq 0)

    $cfg2 = Join-Path $tmp 'bom_config'
    [IO.File]::WriteAllText($cfg2, "#Port 22`n", (New-Object Text.UTF8Encoding($true)))
    $null = Write-ConfigText $cfg2 "Port 2222`n" ($cfg2 + '.bak.1')
    $bytes = [IO.File]::ReadAllBytes($cfg2)
    Check 'Write-ConfigText: a UTF-8 BOM is kept' ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Same 'Write-ConfigText: text after the BOM' "Port 2222`n" ([IO.File]::ReadAllText($cfg2))

    # ReplaceFile fails when the backup name is taken by a folder: the file is written in place.
    $cfg3 = Join-Path $tmp 'fallback_config'
    [IO.File]::WriteAllText($cfg3, "#Port 22`n")
    $null = New-Item -ItemType Directory -Path ($cfg3 + '.bak.dir')
    $how = ''
    try { $how = Write-ConfigText $cfg3 "Port 2222`n" ($cfg3 + '.bak.dir') } catch { $how = 'threw: ' + $_.Exception.Message }
    Same 'Write-ConfigText: when ReplaceFile fails, the file is written in place' 'in place' $how
    Same 'Write-ConfigText: in place, new content' "Port 2222`n" ([IO.File]::ReadAllText($cfg3))
    Check 'Write-ConfigText: in place, no temporary file left' (@(Get-ChildItem -LiteralPath $tmp -Filter 'fallback_config.new-*').Count -eq 0)
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- ACTIVE_SESSIONS=abort: process tree
function P($id, $parent, $name, $path, $created) {
    New-Object PSObject -Property @{ ProcessId = $id; ParentProcessId = $parent; Name = $name; ExecutablePath = $path; CreationDate = $created }
}
$pf = 'C:\Program Files\OpenSSH'
$procs = @(
    (P 4 0 'System' '' '20260926080000.000000+000'),
    (P 600 4 'services.exe' 'C:\Windows\System32\services.exe' '20260926080001.000000+000'),
    (P 700 600 'msiexec.exe' 'C:\Windows\System32\msiexec.exe' '20260926090000.000000+000'),
    (P 2000 600 'sshd.exe' ($pf + '\sshd.exe') '20260926080100.000000+000'),
    # the administrator's session that runs msiexec: kept
    (P 2100 2000 'sshd-session.exe' ($pf + '\sshd-session.exe') '20260926085000.000000+000'),
    (P 2101 2100 'sshd-session.exe' ($pf + '\sshd-session.exe') '20260926085001.000000+000'),
    (P 2200 2101 'cmd.exe' 'C:\Windows\System32\cmd.exe' '20260926085002.000000+000'),
    (P 2300 2200 'msiexec.exe' 'C:\Windows\System32\msiexec.exe' '20260926085900.000000+000'),
    # another user's session: its path is unreadable for a standard user
    (P 3100 2000 'sshd-session.exe' ($pf + '\sshd-session.exe') '20260926084000.000000+000'),
    (P 3101 3100 'sshd-session.exe' '' '20260926084001.000000+000'),
    # Cygwin's sshd: not this package's
    (P 4100 4000 'sshd-session.exe' 'C:\cygwin64\usr\sbin\sshd-session.exe' '20260926084000.000000+000'),
    # a reused PID: the "parent" 5000 started after its child, so it is not an ancestor
    (P 5000 2000 'sshd-session.exe' ($pf + '\sshd-session.exe') '20260926095000.000000+000'),
    (P 5100 5000 'msiexec.exe' 'C:\Windows\System32\msiexec.exe' '20260926090000.000000+000')
)
$keep = Get-KeepSet $procs 999999
Same 'Get-KeepSet: ancestors of the client msiexec' '2000,2100,2101,2200,2300' ((@(2000, 2100, 2101, 2200, 2300) | Where-Object { $keep[$_] }) -join ',')
Check 'Get-KeepSet: a reused PID is not an ancestor' (-not $keep[5000])
Check 'Get-KeepSet: other sessions are not kept' (-not $keep[3100] -and -not $keep[3101])
$open = @(Get-OpenSessions $procs $keep @($pf, 'C:\Windows\System32\OpenSSH'))
Same 'Get-OpenSessions: other sessions, unknown path included, Cygwin and kept ones left out' '3100,3101,5000' ($open -join ',')
Same 'Get-OpenSessions: none when only the installing session runs' '' ((@(Get-OpenSessions @($procs[0..7]) (Get-KeepSet @($procs[0..7]) 999999) @($pf))) -join ',')
Check 'Test-InDirs ignores case and a trailing backslash' (Test-InDirs 'c:\program files\openssh\' @($pf))

# ---------------------------------------------------------------- firewall rules, with a stand-in for HNetCfg.FwPolicy2
# Rules.Item(name) throws for a missing name, as the COM object does; a rule refuses LocalPorts "bad".
Add-Type -TypeDefinition @'
public class PreinstallTestRule {
    public string Name; public int Direction = 1; public int Profiles = 0x7FFFFFFF; public bool Enabled = true;
    public string RemoteAddresses = "*"; public string ApplicationName = @"C:\Program Files\OpenSSH\sshd.exe";
    private string ports = "22";
    public string LocalPorts { get { return ports; } set { if (value == "bad") throw new System.ArgumentException("The parameter is incorrect."); ports = value; } }
    public PreinstallTestRule(string name) { Name = name; }
}
public class PreinstallTestRules : System.Collections.IEnumerable {
    public System.Collections.ArrayList List = new System.Collections.ArrayList();
    public PreinstallTestRule Item(string name) {
        foreach (PreinstallTestRule r in List) { if (r.Name == name) return r; }
        throw new System.IO.FileNotFoundException("The system cannot find the file specified.");
    }
    public System.Collections.IEnumerator GetEnumerator() { return List.GetEnumerator(); }
}
public class PreinstallTestPolicy { public PreinstallTestRules Rules = new PreinstallTestRules(); }
'@
function New-TestPolicy {
    $pol = New-Object PreinstallTestPolicy
    foreach ($r in $args) { $null = $pol.Rules.List.Add($r) }
    return $pol
}
function New-TestRule([string]$name, [int]$direction = 1, [string]$ports = '22', [string]$app = 'C:\Program Files\OpenSSH\sshd.exe') {
    $r = New-Object PreinstallTestRule($name)
    $r.Direction = $direction; $r.LocalPorts = $ports; $r.ApplicationName = $app
    return $r
}
$outbound = New-TestRule $ruleName 2 '1'
$inbound = New-TestRule $ruleName 1 '2222'
$inbound.Profiles = 2; $inbound.Enabled = $false; $inbound.RemoteAddresses = 'LocalSubnet'
$r = Read-FirewallRecord (New-TestPolicy $outbound $inbound)
Check 'Read-FirewallRecord: the inbound rule, also behind an outbound one of the same name' ($r -ne $null -and $r['LocalPorts'] -eq '2222' -and $r['Profiles'] -eq 2 -and $r['Enabled'] -eq $false -and $r['RemoteAddresses'] -eq 'LocalSubnet')
Same 'Read-FirewallRecord: serialised' ('v1|Rule=' + $ruleName + '|LocalPorts=2222|Profiles=2|Enabled=0|RemoteAddresses=LocalSubnet') (ConvertTo-FirewallRecord $r)
$r = Read-FirewallRecord (New-TestPolicy (New-TestRule $altRuleName 1 '2200') (New-TestRule $ruleName 1 '2222'))
Same 'Read-FirewallRecord: the package rule wins over the manager rule' $ruleName $r['Rule']
$r = Read-FirewallRecord (New-TestPolicy (New-TestRule $altRuleName 1 '2200'))
Check 'Read-FirewallRecord: the manager rule when the package rule is missing' ($r -ne $null -and $r['Rule'] -eq $altRuleName -and $r['LocalPorts'] -eq '2200')
$r = Read-FirewallRecord (New-TestPolicy (New-TestRule $altRuleName 1 '22' '%SystemRoot%\System32\OpenSSH\sshd.exe'))
Check 'Read-FirewallRecord: not the in-box server''s rule' ($r -eq $null)
Check 'Read-FirewallRecord: nothing without a rule' ((Read-FirewallRecord (New-TestPolicy (New-TestRule 'Other rule' 1 '22'))) -eq $null)
$a = New-TestRule $ruleName 1 '22'; $b = New-TestRule $ruleName 1 '22'; $o = New-TestRule $ruleName 2 '1'; $x = New-TestRule 'Other rule' 1 '80'
$res = Set-RuleSettings (New-TestPolicy $a $o $b $x) $ruleName @{ LocalPorts = '2222'; Profiles = 3; Enabled = $false; RemoteAddresses = 'LocalSubnet' }
Same 'Set-RuleSettings: every inbound rule of the name' 2 $res['Rules']
Same 'Set-RuleSettings: no errors' 0 $res['Errors'].Count
Check 'Set-RuleSettings: settings applied' ($a.LocalPorts -eq '2222' -and $b.LocalPorts -eq '2222' -and $a.Profiles -eq 3 -and $a.Enabled -eq $false -and $b.RemoteAddresses -eq 'LocalSubnet')
Check 'Set-RuleSettings: outbound and other rules untouched' ($o.LocalPorts -eq '1' -and $o.Profiles -eq 0x7FFFFFFF -and $x.LocalPorts -eq '80')
$res = Set-RuleSettings (New-TestPolicy $a) $ruleName @{ LocalPorts = 'bad'; Profiles = 1 }
Check 'Set-RuleSettings: a refused setting is reported, the others are set' ($res['Rules'] -eq 1 -and $res['Errors'].Count -eq 1 -and $res['Errors'][0] -like 'LocalPorts = bad:*' -and $a.Profiles -eq 1 -and $a.LocalPorts -eq '2222') (($res['Errors']) -join '; ')
$res = Set-RuleSettings (New-TestPolicy $x) $ruleName @{ Profiles = 1 }
Same 'Set-RuleSettings: no rule of the name' 0 $res['Rules']
# The record of the save step applied the way the firewall step and the rollback apply it.
$saved = ConvertFrom-FirewallRecord ('v1|Rule=' + $ruleName + '|LocalPorts=2222|Profiles=2|Enabled=0|RemoteAddresses=10.0.0.0/255.0.0.0')
$fresh = New-TestRule $ruleName 1 '22'
$res = Set-RuleSettings (New-TestPolicy $fresh) $ruleName $saved
Check 'a saved record applied to a re-created rule' ($res['Rules'] -eq 1 -and $fresh.LocalPorts -eq '2222' -and $fresh.Profiles -eq 2 -and $fresh.Enabled -eq $false -and $fresh.RemoteAddresses -eq '10.0.0.0/255.0.0.0')

# ---------------------------------------------------------------- read-only, this machine
try {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    Check 'Get-InboundRule: a missing rule gives $null' ((Get-InboundRule $policy ('no such rule ' + [Guid]::NewGuid())) -eq $null)
    $live = Read-FirewallRecord $policy
    if ($live) {
        $liveLine = ConvertTo-FirewallRecord $live
        $liveBack = ConvertFrom-FirewallRecord $liveLine
        Write-Output ("     live rule: " + $liveLine)
        Check 'live rule: read and serialised' ($liveBack -ne $null -and $liveBack.Count -eq 5) $liveLine
        Check 'live rule: round trip' ($liveBack['LocalPorts'] -eq $live['LocalPorts'] -and $liveBack['Profiles'] -eq $live['Profiles'] -and $liveBack['Enabled'] -eq $live['Enabled'] -and $liveBack['RemoteAddresses'] -eq $live['RemoteAddresses'])
        Write-Output ("     formatted: " + (Format-FirewallRecord $liveBack))
    } else { Write-Output "skip live rule: no inbound '$ruleName' or '$altRuleName' rule on this machine" }
} catch { Write-Output ("skip live rule: " + $_.Exception.Message) }

# reg.exe query output is parsed from an existing REG_SZ value; nothing is written. The script runs
# with ErrorActionPreference Continue, where reg.exe's error output is just text.
$ErrorActionPreference = 'Continue'
$recordKey = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$recordValue = 'ProductName'
$pn = Get-SavedRecord
Check 'Get-SavedRecord: parses reg.exe output' ($pn -like 'Windows*') $pn
$recordValue = 'NoSuchValue' + [Guid]::NewGuid().ToString('N')
Same 'Get-SavedRecord: a missing value gives an empty string' '' (Get-SavedRecord)

Write-Output ''
Write-Output ("passed " + $script:passed + ", failed " + $script:failed)
exit $script:failed
