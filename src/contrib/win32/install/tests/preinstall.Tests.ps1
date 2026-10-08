# Tests for ..\preinstall.ps1 that need neither administrator rights nor an installation.
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File src\contrib\win32\install\tests\preinstall.Tests.ps1
# Exit code: the number of failed checks. Written for Windows PowerShell 2.0 and later, like the
# script it tests. It dot-sources preinstall.ps1 with -Phase functions, which defines the functions
# and returns before any phase runs.
# - static: the script parses, uses no PowerShell 3+ syntax the tests know of (nor do install-sshd.ps1,
#   uninstall-sshd.ps1 and OpenSSHUtils.psm1), every function has a caller, and the two scripts
#   that openssh.wixproj embeds (see there) keep every statement of their regions and fit on the
#   powershell.exe command line; when a build has written obj\<platform>\Release\preinstall.wxi,
#   its content is compared with the scripts made here.
# - pure functions: firewall and service records (de)serialisation, kept start types and what the
#   restore and rollback steps do with them, FIREWALL_PROFILES and SSHD_PORT parsing, sshd_config
#   Port editing, backup names, the listeners of a port in netstat output, the process-tree logic of
#   ACTIVE_SESSIONS=abort, the start type that .github\scripts\Test-Installer.ps1 checks.
# - files: sshd_config is replaced by a rename in a temporary folder; the permissions of the file
#   (protected or inherited) and a UTF-8 BOM are kept, a previous file is put back byte for byte,
#   and a backup that cannot be written is not left behind.
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
function Get-Ps3Constructs([string]$code) {
    $errs = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($code, [ref]$errs)
    $ps3 = @()
    $command = ''
    $outer = New-Object System.Collections.Stack   # the command around a parenthesis or a script block
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $tk = $tokens[$i]; $c = [string]$tk.Content; $ty = [string]$tk.Type
        if ($ty -eq 'Command') { $command = $c.ToLower() }
        elseif ($ty -eq 'GroupStart') { $outer.Push($command); $command = '' }
        elseif ($ty -eq 'GroupEnd') { $command = ''; if ($outer.Count -gt 0) { $command = $outer.Pop() } }
        elseif (@('NewLine', 'StatementSeparator') -contains $ty) { $command = '' }
        if ($ty -eq 'Operator' -and @('-in', '-notin', '-shl', '-shr') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'Type' -and @('ordered', 'pscustomobject', 'nullstring') -contains $c.ToLower()) { $ps3 += ('[' + $c + '] (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'Member' -and @('new', 'where', 'foreach', 'isnullorwhitespace') -contains $c.ToLower()) { $ps3 += ('.' + $c + ' (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'Command' -and @('get-ciminstance', 'invoke-cimmethod', 'get-netfirewallrule', 'set-netfirewallrule', 'new-netfirewallrule', 'get-nettcpconnection', 'convertto-json', 'convertfrom-json', 'invoke-webrequest', 'invoke-restmethod', 'get-filehash') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'CommandParameter' -and @('-raw', '-nonewline') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
        # -File and -Directory of the file system provider (PowerShell 3.0)
        if ($ty -eq 'CommandParameter' -and @('-file', '-directory') -contains $c.ToLower() -and @('get-childitem', 'gci', 'dir', 'ls') -contains $command) { $ps3 += ($command + ' ' + $c + ' (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'Variable' -and $c.ToLower() -eq 'psitem') { $ps3 += ('$PSItem (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'CommandArgument' -and $c -eq 'Ignore' -and $i -gt 0 -and [string]$tokens[$i - 1].Content -match '^-(ErrorAction|EA|WarningAction|WA)$') { $ps3 += ('-ErrorAction Ignore (line ' + $tk.StartLine + ')') }
        if ($ty -eq 'Keyword' -and @('class', 'enum', 'using', 'workflow') -contains $c.ToLower()) { $ps3 += ($c + ' (line ' + $tk.StartLine + ')') }
    }
    return $ps3
}
$ps3 = @(Get-Ps3Constructs $text)
Check 'no PowerShell 3+ syntax, cmdlets or parameters known to the lint' ($ps3.Count -eq 0) ($ps3 -join ', ')
Same 'the lint finds Get-ChildItem -File, .Where() and IsNullOrWhiteSpace' 3 (@(Get-Ps3Constructs "Get-ChildItem -Path (Join-Path `$d '*') -Include *.exe -File | % { }`n`$a.Where({ `$_ })`n[string]::IsNullOrWhiteSpace('')").Count)
Same 'the lint leaves -File of other commands alone' 0 (@(Get-Ps3Constructs "powershell.exe -File x.ps1`nGet-ChildItem (Split-Path -Leaf x) | Out-File -FilePath y").Count)
# The ZIP-style scripts next to the binaries (install-sshd.ps1 deletes the services before it
# re-creates them: a PowerShell 2.0 error in between left none).
foreach ($f in @('install-sshd.ps1', 'uninstall-sshd.ps1', 'OpenSSHUtils.psm1')) {
    $path = Join-Path $srcRoot ('contrib\win32\openssh\' + $f)
    $found = @(Get-Ps3Constructs ([IO.File]::ReadAllText($path)))
    Check ($f + ': no PowerShell 3+ syntax, cmdlets or parameters known to the lint') ($found.Count -eq 0) ($found -join ', ')
}

# Every function of the script is used by the script, and the restore after a failed port change
# no longer goes through File.Replace (PowerShell 2.0 passed $null as "", which threw).
$functions = @([regex]::Matches($text, '(?m)^\s*function\s+([\w-]+)') | ForEach-Object { $_.Groups[1].Value })
$unused = @($functions | Where-Object { [regex]::Matches($text, '(?<![\w-])' + [regex]::Escape($_) + '(?![\w-])').Count -lt 2 })
Check ('every function of preinstall.ps1 has a caller (' + $functions.Count + ' functions)') ($unused.Count -eq 0) ($unused -join ', ')
Check 'preinstall.ps1 does not call File.Replace' (-not ($text -match '\[IO\.File\]::Replace\('))

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
Check 'the service and port rollback phases are in the firewall script only' ($fw.Contains("Phase -eq 'svcrestore'") -and $fw.Contains("Phase -eq 'portrollback'") -and -not $pre.Contains("Phase -eq 'svcrestore'"))
# Phase "pre" stops running services before StopServices, so only this record lets a rollback start
# them again: the save step writes it before any of its exits.
$fwsave = $text.Substring($text.IndexOf("if (`$Phase -eq 'fwsave')"))
$fwsave = $fwsave.Substring(0, $fwsave.IndexOf('exit 0'))
Check 'fwsave records the services before it can exit' ($fwsave.Contains('(Save-Record $services $serviceValue)')) $fwsave
# When phase port cannot write sshd_config (the file is unchanged), the record no longer names a
# backup, which may be incomplete: phase portrollback would write it over sshd_config.
$portFail = $text.Substring($text.IndexOf("if (`$Phase -eq 'port')"))
$portFail = $portFail.Substring($portFail.IndexOf('try { Write-ConfigText $cfg $new $backup } catch {'))
$portFail = $portFail.Substring(0, $portFail.IndexOf('exit 0'))
Check 'phase port: a failed write removes the backup name from the record' ($portFail.Contains('if (-not $created) { Remove-Record $portValue }')) $portFail

# ---------------------------------------------------------------- load the functions
. $Script -Phase functions

# Exercise the actual phase setup: an empty REMOVE is also a fresh client-only install.
. $Script -Phase functions -ServerAction none -ClientAction install -SharedAction install
Check 'client-only install leaves sshd and its sessions alone' (-not $touchServer -and $touchClient -and $touchShared)
. $Script -Phase functions -Remove ALL -ServerAction none -ClientAction remove -SharedAction remove
Check 'client-only uninstall leaves the existing server alone' (-not $touchServer -and $touchClient -and $touchShared)
. $Script -Phase functions -Remove Server -ServerAction remove -ClientAction none -SharedAction none
Check 'server feature removal preserves the remaining client and shared service' ($touchServer -and -not $touchClient -and -not $touchShared)
. $Script -Phase functions -ServerAction install -ClientAction install -SharedAction install
Check 'full install touches both selected features and shared files' ($touchServer -and $touchClient -and $touchShared)
. $Script -Phase functions
Check 'missing feature actions never imply permission to stop services' (-not $touchServer -and -not $touchClient -and -not $touchShared)
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
    @('equals-delimited Match stays after the global Port', "Match=all`nPasswordAuthentication no`n", "Port 2222`n`nMatch=all`nPasswordAuthentication no`n"),
    @('before the first Include', "LogLevel INFO`nInclude conf.d/*.conf`nMatch all`n", "LogLevel INFO`nPort 2222`nInclude conf.d/*.conf`nMatch all`n"),
    @('commented example before Match', "#Port 22`nMatch all`n#Port 23`n", "Port 2222`nMatch all`n#Port 23`n"),
    @('no final line break is kept', "#Port 22`nLogLevel INFO", "Port 2222`nLogLevel INFO"),
    @('appended at the end with a line break', "LogLevel INFO", "LogLevel INFO`nPort 2222`n"),
    @('empty file', "", "Port 2222`n"),
    @('before the rules section of OpenSSH Server Manager 1.6.0', ("LogLevel INFO`n" + $managerRegions[0] + "`nMatch User x`n"), ("LogLevel INFO`nPort 2222`n`n" + $managerRegions[0] + "`nMatch User x`n")),
    @('before the rules section of OpenSSH Server PN Manager', ("LogLevel INFO`n" + $managerRegions[1] + "`nMatch User x`n"), ("LogLevel INFO`nPort 2222`n`n" + $managerRegions[1] + "`nMatch User x`n")),
    @('before the SFTP section of OpenSSH Server PN Manager', ("LogLevel INFO`n" + $managerRegions[2] + "`nMatch Group sftp`n"), ("LogLevel INFO`nPort 2222`n`n" + $managerRegions[2] + "`nMatch Group sftp`n")),
    @('PortForwarding-like keyword is not Port', "PortX 1`n", "PortX 1`nPort 2222`n")
)
foreach ($c in $cases) {
    $got = Set-SshdConfigPortText $c[1] 2222
    Check ('Set-SshdConfigPortText: ' + $c[0]) ($got -ceq $c[2]) ('expected [' + (Show $c[2]) + '] got [' + (Show $got) + ']')
}
Same 'Get-SshdConfigPorts: several Port lines' '2222,2200' ((Get-SshdConfigPorts "Port 2222`nPort 2200`nPort 2222`n") -join ',')
Same 'Get-SshdConfigPorts: explicit ListenAddress ports and default for a bare IPv6 address' '2022,2023,22' ((Get-SshdConfigPorts "ListenAddress 0.0.0.0:2022`nListenAddress [::1]:2023`nListenAddress ::1`n") -join ',')
Same 'Get-SshdConfigPorts: explicit ListenAddress overrides Port' '2022' ((Get-SshdConfigPorts "ListenAddress 0.0.0.0:2022`nPort 2200`n") -join ',')
Same 'Get-SshdConfigPorts: portless ListenAddress expands all global ports' '2022,2200,2201' ((Get-SshdConfigPorts "ListenAddress 127.0.0.1:2022`nListenAddress [::1]`nPort 2200`nPort 2201`n") -join ',')
Same 'Get-SshdConfigPorts: explicit IPv6 port excludes default' '2022' ((Get-SshdConfigPorts "ListenAddress [::1]:2022`n") -join ',')
Same 'Get-SshdConfigPorts: deduplicates explicit and global ports' '2200' ((Get-SshdConfigPorts "ListenAddress 127.0.0.1:2200`nListenAddress ::1`nPort 2200`n") -join ',')
Same 'Get-SshdConfigPorts: IPv6 tail is not a port' '22' ((Get-SshdConfigPorts "ListenAddress ::2022`n") -join ',')
Same 'Get-SshdConfigPorts: inside Match ignored' '22' ((Get-SshdConfigPorts "Match all`nPort 2200`n") -join ',')
Same 'Get-SshdConfigPorts: equals-delimited Match ignored' '22' ((Get-SshdConfigPorts "Match=all`nPort 2200`n") -join ',')

# ---------------------------------------------------------------- SSHD_PORT: who listens on the port
$netstat = @"

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    0.0.0.0:2222           0.0.0.0:0              LISTENING       900
  TCP    10.0.0.1:2222          10.0.0.9:51000         ESTABLISHED     1234
  TCP    127.0.0.1:22222        0.0.0.0:0              LISTENING       77
  TCP    [::]:2222              [::]:0                 ABH$([char]0xD6)REN         1234
  TCP    [fe80::1%5]:2222       [fe80::9%5]:51001      ESTABLISHED     1234
  UDP    0.0.0.0:2222           *:*                                    555
"@
Same 'Get-PortListenerPids: IPv4 and IPv6 listeners, localized state, no connections or UDP' '900,1234' ((Get-PortListenerPids $netstat 2222) -join ',')
Same 'Get-PortListenerPids: another port' '77' ((Get-PortListenerPids $netstat 22222) -join ',')
Same 'Get-PortListenerPids: nobody' '' ((Get-PortListenerPids $netstat 22) -join ',')
Check 'Test-PortOwnedBySshd: another process on the IPv4 wildcard is a conflict' (-not (Test-PortOwnedBySshd (Get-PortListenerPids $netstat 2222) 1234))
Check 'Test-PortOwnedBySshd: only the sshd process' (Test-PortOwnedBySshd @(1234) 1234)
Check 'Test-PortOwnedBySshd: listeners of another process only' (-not (Test-PortOwnedBySshd @(900) 1234))
Check 'Test-PortOwnedBySshd: nobody listens' (-not (Test-PortOwnedBySshd @() 1234))
Check 'Test-PortOwnedBySshd: sshd not running (PID 0)' (-not (Test-PortOwnedBySshd @(900) 0))

# ---------------------------------------------------------------- services: record, kept start types, plans
foreach ($c in @(@(4, $null, 'disabled'), @(4, 1, 'disabled'), @(2, 1, 'delayed-auto'), @(2, 0, ''), @(2, $null, ''), @(3, $null, ''), @(3, 1, ''), @($null, $null, ''))) {
    Same ('Get-KeptStart Start=' + $c[0] + ' DelayedAutostart=' + $c[1]) $c[2] (Get-KeptStart $c[0] $c[1])
}
$pf = 'C:\Program Files\OpenSSH'
$states = @{
    'sshd' = @{ Running = $false; Start = 4; Delayed = $null; Dir = $pf };
    'ssh-agent' = @{ Running = $true; Start = 2; Delayed = 1; Dir = 'c:\program files\openssh' }
}
$inboxDir = 'C:\Windows\System32\OpenSSH'
Same 'ConvertTo-ServiceRecord: Disabled and Automatic (Delayed Start) of this package''s services' 'v1|sshd=0,disabled|ssh-agent=1,delayed-auto' (ConvertTo-ServiceRecord $states $inboxDir)
$x86 = @{ 'sshd' = @{ Running = $false; Start = 4; Delayed = $null; Dir = 'C:\Program Files (x86)\OpenSSH' } }
Same 'ConvertTo-ServiceRecord: a package''s service in another folder (x86 -> x64, INSTALLFOLDER not passed again) keeps Disabled' 'v1|sshd=0,disabled' (ConvertTo-ServiceRecord $x86 $inboxDir)
$inbox = @{ 'sshd' = @{ Running = $true; Start = 3; Delayed = $null; Dir = $inboxDir }; 'ssh-agent' = @{ Running = $false; Start = 4; Delayed = $null; Dir = 'c:\windows\system32\openssh' } }
Same 'ConvertTo-ServiceRecord: in-box registrations keep no start type (Windows'' defaults)' 'v1|sshd=1,|ssh-agent=0,' (ConvertTo-ServiceRecord $inbox $inboxDir)
Same 'ConvertTo-ServiceRecord: no service registered' 'v1' (ConvertTo-ServiceRecord @{} $inboxDir)
$back = ConvertFrom-ServiceRecord 'v1|sshd=0,disabled|ssh-agent=1,delayed-auto'
Check 'ConvertFrom-ServiceRecord: round trip' ($back.Count -eq 2 -and -not $back['sshd'].Running -and $back['sshd'].Start -eq 'disabled' -and $back['ssh-agent'].Running -and $back['ssh-agent'].Start -eq 'delayed-auto')
$bad = ConvertFrom-ServiceRecord "v1|sshd=1,demand|Spooler=1,|ssh-agent=2,|sshd-x=1,|ssh-agent=1,disabled';calc;'"
Check 'ConvertFrom-ServiceRecord: other names, states and start types are dropped' ($bad.Count -eq 0) (($bad.Keys | ForEach-Object { $_ }) -join ',')
Check 'ConvertFrom-ServiceRecord: other version' ((ConvertFrom-ServiceRecord 'v2|sshd=1,').Count -eq 0)
Check 'ConvertFrom-ServiceRecord: empty' ((ConvertFrom-ServiceRecord '').Count -eq 0)
# Upgrade or repair: InstallServices made both Automatic, StartServices started them.
$now = @{ 'sshd' = @{ Running = $true; Start = 2; Delayed = 0; Dir = $pf }; 'ssh-agent' = @{ Running = $true; Start = 2; Delayed = 0; Dir = $pf } }
Same 'Get-ServicePlan: Disabled again and stopped, Delayed Start again' 'config sshd disabled|stop sshd|config ssh-agent delayed-auto' ((Get-ServicePlan $back $now $false) -join '|')
Same 'Get-ServicePlan: nothing when the start type is still the kept one' '' ((Get-ServicePlan $back @{ 'sshd' = @{ Running = $false; Start = 4; Delayed = $null }; 'ssh-agent' = @{ Running = $true; Start = 2; Delayed = 1 } } $false) -join '|')
Same 'Get-ServicePlan: nothing without a kept start type' '' ((Get-ServicePlan (ConvertFrom-ServiceRecord 'v1|sshd=1,|ssh-agent=1,') $now $false) -join '|')
Same 'Get-ServicePlan: a service that is not registered is left alone' '' ((Get-ServicePlan $back @{} $true) -join '|')
# Rollback: the old package's services are registered again but stopped (phase pre stopped them).
$stopped = @{ 'sshd' = @{ Running = $false; Start = 2; Delayed = 0 }; 'ssh-agent' = @{ Running = $false; Start = 2; Delayed = 0 } }
Same 'Get-ServicePlan, rollback: the running services are started again' 'start sshd|start ssh-agent' ((Get-ServicePlan (ConvertFrom-ServiceRecord 'v1|sshd=1,|ssh-agent=1,') $stopped $true) -join '|')
Same 'Get-ServicePlan, rollback: a stopped service stays stopped' 'start ssh-agent' ((Get-ServicePlan (ConvertFrom-ServiceRecord 'v1|sshd=0,|ssh-agent=1,') $stopped $true) -join '|')
Same 'Get-ServicePlan, rollback: kept start types again, a Disabled service is not started' 'config sshd disabled|config ssh-agent delayed-auto|start ssh-agent' ((Get-ServicePlan (ConvertFrom-ServiceRecord 'v1|sshd=1,disabled|ssh-agent=1,delayed-auto') $stopped $true) -join '|')
Same 'Get-ServicePlan, no rollback: nothing is started' '' ((Get-ServicePlan (ConvertFrom-ServiceRecord 'v1|sshd=1,|ssh-agent=1,') $stopped $false) -join '|')

# The record is one key with several values: deleting one leaves the others (fwsave writes the
# services first and may then delete a leftover firewall record). reg.exe is replaced by a stand-in.
$script:regCalls = @()
function RegStandIn { $script:regCalls += ($args -join ' '); $global:LASTEXITCODE = 0 }
$realReg = $reg; $reg = 'RegStandIn'
Remove-Record; Remove-Record $portValue; Remove-Record ''
$reg = $realReg
Same 'Remove-Record: one value, or the whole key with ''''' ('delete ' + $recordKey + ' /v FirewallRule /f|delete ' + $recordKey + ' /v SshdConfig /f|delete ' + $recordKey + ' /f') ($script:regCalls -join '|')

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
    $out = @(Write-ConfigText $cfg (Set-SshdConfigPortText $old 2222) $backup)
    Same 'Write-ConfigText: no output' 0 $out.Count
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

    # The backup name is taken by a folder: never truncate the live config.
    $cfg3 = Join-Path $tmp 'fallback_config'
    [IO.File]::WriteAllText($cfg3, "#Port 22`n")
    $null = New-Item -ItemType Directory -Path ($cfg3 + '.bak.dir')
    $how = ''
    try { $how = Write-ConfigText $cfg3 "Port 2222`n" ($cfg3 + '.bak.dir') } catch { $how = 'threw: ' + $_.Exception.Message }
    Check 'Write-ConfigText: failed atomic replacement is reported' ($how -like 'threw:*') $how
    Same 'Write-ConfigText: failed replacement keeps original content' "#Port 22`n" ([IO.File]::ReadAllText($cfg3))
    Check 'Write-ConfigText: failed replacement leaves no temporary file' (@(Get-ChildItem -LiteralPath $tmp -Filter 'fallback_config.new-*').Count -eq 0)

    # The rename keeps an inherited DACL exactly: no explicit copies of the inherited entries.
    $cfg4 = Join-Path $tmp 'inherited_config'
    [IO.File]::WriteAllText($cfg4, "#Port 22`n")
    $inherited = [IO.File]::GetAccessControl($cfg4).GetSecurityDescriptorSddlForm('Access')
    Write-ConfigText $cfg4 "Port 2222`n" ''
    Same 'Write-ConfigText: an inherited DACL stays inherited' $inherited ([IO.File]::GetAccessControl($cfg4).GetSecurityDescriptorSddlForm('Access'))
    Check 'Write-ConfigText: without a backup name, no backup' (@(Get-ChildItem -LiteralPath $tmp -Filter 'inherited_config*').Count -eq 1)

    # The rollback of a failed port change: the previous file back, byte for byte, with the
    # permissions of the live file, and no file left beside it (before, File.Replace with a $null
    # backup name threw "The path is not of a legal form" and nothing was put back).
    $cfg5 = Join-Path $tmp 'restore_config'
    [IO.File]::WriteAllText($cfg5, "Port 2222`r`n", (New-Object Text.UTF8Encoding($false)))
    $fs = New-Object Security.AccessControl.FileSecurity   # a persisted one writes nothing again
    $fs.SetSecurityDescriptorSddlForm($sddl, 'Access')
    [IO.File]::SetAccessControl($cfg5, $fs)
    $prev = [byte[]](0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes("#Port 22`r`nLogLevel INFO`n")
    $err = ''
    try { Write-ConfigBytes $cfg5 ([byte[]]$prev) '' } catch { $err = $_.Exception.Message }
    Check 'Write-ConfigBytes: puts a file back without a backup name' ($err -eq '') $err
    Same 'Write-ConfigBytes: the previous bytes are back exactly' ([BitConverter]::ToString([byte[]]$prev)) ([BitConverter]::ToString([IO.File]::ReadAllBytes($cfg5)))
    Same 'Write-ConfigBytes: the permissions of the live file are kept' $before ([IO.File]::GetAccessControl($cfg5).GetSecurityDescriptorSddlForm('Access'))
    Check 'Write-ConfigBytes: no other file left' (@(Get-ChildItem -LiteralPath $tmp -Filter 'restore_config*').Count -eq 1) ((@(Get-ChildItem -LiteralPath $tmp -Filter 'restore_config*') | ForEach-Object { $_.Name }) -join ', ')

    # The backup cannot be written (its permissions, those of the live file, allow this account to
    # read only): no empty backup is left for phase portrollback to put back over sshd_config.
    $cfg6 = Join-Path $tmp 'readonly_config'
    [IO.File]::WriteAllText($cfg6, "#Port 22`n")
    $fs = New-Object Security.AccessControl.FileSecurity
    $fs.SetSecurityDescriptorSddlForm('D:P(A;;FR;;;' + $me + ')', 'Access')
    [IO.File]::SetAccessControl($cfg6, $fs)
    $err = ''
    try { Write-ConfigText $cfg6 "Port 2222`n" ($cfg6 + '.bak.20260926-140509') } catch { $err = $_.Exception.Message }
    Check 'Write-ConfigText: a backup that cannot be written is reported' ($err -ne '')
    Same 'Write-ConfigText: the live file is unchanged' "#Port 22`n" ([IO.File]::ReadAllText($cfg6))
    Check 'Write-ConfigText: no empty or partial backup left' (@(Get-ChildItem -LiteralPath $tmp -Filter 'readonly_config*').Count -eq 1) ((@(Get-ChildItem -LiteralPath $tmp -Filter 'readonly_config*') | ForEach-Object { $_.Name }) -join ', ')
    # Remove-Item -Force would first set the attributes, which these permissions do not allow.
    Get-ChildItem -LiteralPath $tmp -Filter 'readonly_config*' | ForEach-Object { [IO.File]::Delete($_.FullName) }
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

# ---------------------------------------------------------------- CI: .github\scripts\Test-Installer.ps1
# ServiceController.StartType reports Automatic (Delayed Start) as Automatic, so the upgrade check of
# the kept delayed start reads the service's DelayedAutostart value; here from a registry stand-in.
if ('System.Management.Automation.Language.Parser' -as [type]) {
    $ci = Join-Path (Split-Path -Parent $srcRoot) '.github\scripts\Test-Installer.ps1'
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ci, [ref]$t, [ref]$e)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ServiceStartType' }, $true)
    Check 'Test-Installer.ps1: the service checks read the start type through Get-ServiceStartType' (($fn -ne $null) -and $ast.Extent.Text.Contains('$start = if ($svc) { Get-ServiceStartType $Name $svc }'))
    if ($fn) {
        & {
            function Get-ItemProperty { $values }
            . ([scriptblock]::Create($fn.Extent.Text))
            $auto = New-Object PSObject -Property @{ StartType = 'Automatic' }
            $values = New-Object PSObject -Property @{ Start = 2; DelayedAutostart = 1 }
            Same 'Get-ServiceStartType: Automatic with DelayedAutostart 1 is a delayed start' 'AutomaticDelayedStart' (Get-ServiceStartType 'sshd' $auto)
            $values = New-Object PSObject -Property @{ Start = 2; DelayedAutostart = 0 }
            Same 'Get-ServiceStartType: Automatic with DelayedAutostart 0' 'Automatic' (Get-ServiceStartType 'sshd' $auto)
            $values = New-Object PSObject -Property @{ Start = 2 }
            Same 'Get-ServiceStartType: Automatic without DelayedAutostart' 'Automatic' (Get-ServiceStartType 'sshd' $auto)
            $values = New-Object PSObject -Property @{ Start = 4; DelayedAutostart = 1 }
            Same 'Get-ServiceStartType: Disabled stays Disabled' 'Disabled' (Get-ServiceStartType 'sshd' (New-Object PSObject -Property @{ StartType = 'Disabled' }))
        }
    }
}

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
