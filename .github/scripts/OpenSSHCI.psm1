<#
.SYNOPSIS
    Helpers for the install tests in .github/workflows/openssh.yml: run msiexec, read MSI properties,
    check the services, the banner and the firewall rule, run OpenSSH Server Manager's test modes, and
    collect the results of a group of checks.

.DESCRIPTION
    Every check is recorded with Test-Check under a mode:
      enforce  a failed check fails the step (Complete-Checks throws)
      report   a failed check is only a warning annotation
      skip     the check is not evaluated
    The modes for features that are still being implemented come from environment variables set in
    the workflow (FIREWALL_PRESERVATION_CHECK, SSHD_PORT_CHECK, ACTIVE_SESSIONS_CHECK), so they can be
    switched without editing this file.

    Needs an elevated PowerShell 7 on Windows (GitHub's Windows runners are elevated).

.EXAMPLE
    Import-Module ./.github/scripts/OpenSSHCI.psm1
    Get-MsiInfo .\OpenSSH-Win64-v10.5.1.0.msi
#>

Set-StrictMode -Version 3.0

$script:RuleName = 'OpenSSH SSH Server Preview (sshd)'   # FirewallException/@Name in src/contrib/win32/install/server.wxs
$script:ProductName = 'OpenSSH Server PN'                 # Product/@Name in product.wxs
$script:Checks = New-Object System.Collections.Generic.List[object]

function Get-OpenSSHInstallDir { Join-Path $env:ProgramFiles 'OpenSSH' }

function Write-Annotation {
    param(
        [ValidateSet('error', 'warning', 'notice')][string]$Level,
        [string]$Message,
        [string]$Title = ''
    )
    $clean = ($Message -replace "`r?`n", ' ')
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $t = if ($Title) { " title=$Title" } else { '' }
        Write-Host "::$Level$t::$clean"
    } else {
        Write-Host "[$Level] $Title $clean"
    }
}

function Invoke-Native {
    <# Runs a program, returns exit code and the combined output. Output is not written to the error stream. #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Arguments = '',
        [int]$TimeoutSeconds = 300
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { try { $p.Kill() } catch { Write-Verbose "already exited: $_" } ; throw "$FilePath $Arguments did not finish within $TimeoutSeconds s" }
    $p.WaitForExit()
    [pscustomobject]@{ ExitCode = $p.ExitCode; Output = ($out.Result + $err.Result).Trim() }
}

function Get-MsiInfo {
    <# Reads ProductCode, UpgradeCode, ProductVersion, ProductName and Manufacturer from an MSI file (read-only). #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($full, 0))
    $info = [ordered]@{ File = Split-Path $full -Leaf }
    try {
        foreach ($name in 'ProductCode', 'UpgradeCode', 'ProductVersion', 'ProductName', 'Manufacturer') {
            $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'"))
            $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            $info[$name] = if ($record) { $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1) } else { $null }
            $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
        }
    } finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    }
    $info['Sha256'] = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]$info
}

function New-FailingMsi {
    <#
      A copy of an MSI that fails late on purpose, to test the rollback: one deferred custom action
      ("CITestFailAfterStart", cmd.exe /c exit 1) sequenced at 5950, after StartServices (5900) and
      before InstallFinalize (6600), with a new package code. Files, services and the firewall rule are
      installed and the old product is removed before it runs; Windows Installer then rolls everything
      back. A broken sshd_config cannot be used instead: sshd reports SERVICE_RUNNING before it reads
      its configuration (wmain_sshd.c), so StartServices succeeds and the process exits afterwards.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $full = (Resolve-Path -LiteralPath $Destination).Path
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($full, 1))   # 1 = transact
    try {
        # Type 1058 = 1024 (deferred) + 34 (an executable named in Target, working directory from the Directory table).
        $statements = @(
            "INSERT INTO ``CustomAction`` (``Action``, ``Type``, ``Source``, ``Target``) VALUES ('CITestFailAfterStart', 1058, 'TARGETDIR', '""[SystemFolder]cmd.exe"" /c exit 1')",
            "INSERT INTO ``InstallExecuteSequence`` (``Action``, ``Condition``, ``Sequence``) VALUES ('CITestFailAfterStart', 'NOT Installed', 5950)"
        )
        foreach ($sql in $statements) {
            $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql))
            $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
            $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        }
        # A package code of its own (summary property 9): the copy is another package, not the release package.
        $summary = $db.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $db, @(1))
        [void]$summary.GetType().InvokeMember('Property', 'SetProperty', $null, $summary, @(9, ('{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}')))
        [void]$summary.GetType().InvokeMember('Persist', 'InvokeMethod', $null, $summary, $null)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($summary)
        $db.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $db, $null) | Out-Null
    } finally {
        # A database opened for writing stays open, and the file locked, until every handle is gone: views, summary
        # information and the database itself. msiexec could not open the file otherwise (1619).
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    $full
}

function Get-MsiTableRows {
    <# The rows of one MSI table (read-only), as objects with the given columns. #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Table,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )
    $full = (Resolve-Path -LiteralPath $Path).Path
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($full, 0))
    $rows = @()
    $columnList = ($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', '
    try {
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT $columnList FROM ``$Table``"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        while ($true) {
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if (-not $record) { break }
            $row = [ordered]@{}
            for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, ($i + 1)) }
            $rows += [pscustomobject]$row
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)
        }
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
    } finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    $rows
}

function Invoke-Msiexec {
    <#
      Runs msiexec silently with a verbose log and returns its exit code. -Arguments are the action and
      properties, e.g. '/i', '"C:\x.msi"', 'ALLOWDOWNGRADE=1'. Exit codes outside -AllowedExitCodes throw.
      1618 (another installation is in progress) is retried for up to five minutes.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [int[]]$AllowedExitCodes = @(0)
    )
    $line = (@($Arguments) + @('/qn', '/norestart', '/l*v', ('"' + $LogPath + '"'))) -join ' '
    $deadline = (Get-Date).AddMinutes(5)
    while ($true) {
        Write-Host "msiexec $line"
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $line -Wait -PassThru
        $code = $p.ExitCode
        Write-Host "msiexec exit code $code after $([math]::Round($watch.Elapsed.TotalSeconds)) s; log $LogPath"
        if ($code -ne 1618 -or (Get-Date) -gt $deadline) { break }
        Write-Host 'Another installation is in progress (1618); retrying in 20 s.'
        Start-Sleep -Seconds 20
    }
    if ($AllowedExitCodes -notcontains $code) {
        if (Test-Path -LiteralPath $LogPath) {
            Write-Host '-- last 60 lines of the MSI log with "error", "return value 3" or "preinstall:"'
            Select-String -LiteralPath $LogPath -Pattern 'error|return value 3|preinstall:' | Select-Object -Last 60 | ForEach-Object { Write-Host $_.Line }
        }
        throw "msiexec returned $code (allowed: $($AllowedExitCodes -join ', '))"
    }
    $code
}

function Get-InstalledOpenSSHProduct {
    <# The installed OpenSSH Server PN product (from the Uninstall registry keys), or $null. #>
    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem $root) {
            $p = Get-ItemProperty $key.PSPath
            if ($p.PSObject.Properties['DisplayName'] -and $p.DisplayName -eq $script:ProductName) {
                return [pscustomobject]@{ ProductCode = $key.PSChildName; DisplayVersion = $p.DisplayVersion; Publisher = $p.Publisher; Key = $key.Name }
            }
        }
    }
    $null
}

function Get-SshBanner {
    <# Connects to the port and returns the identification string sshd sends first, or $null. #>
    param([int]$Port = 22, [string]$Address = '127.0.0.1', [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.ReceiveTimeout = 5000
            $client.Connect($Address, $Port)
            $buffer = New-Object byte[] 256
            $n = $client.GetStream().Read($buffer, 0, $buffer.Length)
            if ($n -gt 0) { return ([Text.Encoding]::ASCII.GetString($buffer, 0, $n)).Trim() }
        } catch {
            Start-Sleep -Seconds 1
        } finally {
            $client.Dispose()
        }
    } while ((Get-Date) -lt $deadline)
    $null
}

function Get-SshdListenPort {
    <# TCP ports the process of the sshd service listens on. #>
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if (-not $svc -or -not $svc.ProcessId) { return @() }
    @(Get-NetTCPConnection -State Listen -OwningProcess $svc.ProcessId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
}

function Get-SshdFirewallRule {
    <# The inbound rules named like the package's rule, with port, program and profile mask (0 = all profiles). #>
    @(Get-NetFirewallRule -DisplayName $script:RuleName -ErrorAction SilentlyContinue | ForEach-Object {
        $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_
        $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_
        [pscustomobject]@{
            Enabled     = ("$($_.Enabled)" -eq 'True')
            Direction   = "$($_.Direction)"
            Action      = "$($_.Action)"
            Profile     = "$($_.Profile)"
            ProfileMask = [int]$_.Profile
            Protocol    = "$($port.Protocol)"
            LocalPort   = (@($port.LocalPort) -join ',')
            Program     = "$($app.Program)"
        }
    })
}

function Get-DefaultFirewallProfileMask {
    <# What the installer sets without FIREWALL_PROFILES: all profiles (0) on Windows Server, Domain and Private (3) on client editions. #>
    $productType = (Get-CimInstance Win32_OperatingSystem).ProductType   # 1 workstation, 2 domain controller, 3 server
    if ($productType -eq 1) { 3 } else { 0 }
}

function Reset-Checks { $script:Checks.Clear() }

function Test-Check {
    <# Records one check. -Mode enforce|report|skip. Returns $true when it passed (or was skipped). #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Condition,
        [string]$Detail = '',
        [ValidateSet('enforce', 'report', 'skip')][string]$Mode = 'enforce'
    )
    if ($Mode -eq 'skip') {
        $script:Checks.Add([pscustomobject]@{ Name = $Name; Result = 'SKIP'; Mode = $Mode; Detail = $Detail })
        Write-Host "SKIP  $Name"
        return $true
    }
    $result = if ($Condition) { 'PASS' } elseif ($Mode -eq 'report') { 'WARN' } else { 'FAIL' }
    $script:Checks.Add([pscustomobject]@{ Name = $Name; Result = $result; Mode = $Mode; Detail = $Detail })
    Write-Host ("{0}  {1}{2}" -f $result, $Name, $(if ($Detail) { "  ($Detail)" } else { '' }))
    if ($result -eq 'FAIL') { Write-Annotation error "$Name $Detail" 'Check failed' }
    if ($result -eq 'WARN') { Write-Annotation warning "$Name $Detail" 'Check failed (report only)' }
    $Condition
}

function Complete-Checks {
    <# Writes the recorded checks to the job summary and throws when an enforced check failed. #>
    param([Parameter(Mandatory = $true)][string]$Title)
    $failed = @($script:Checks | Where-Object { $_.Result -eq 'FAIL' })
    if ($env:GITHUB_STEP_SUMMARY) {
        $lines = @("#### $Title", '', '| Result | Check | Detail |', '|---|---|---|')
        foreach ($c in $script:Checks) { $lines += "| $($c.Result) | $($c.Name) | $(($c.Detail -replace '\|', '/')) |" }
        $lines += ''
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $lines -Encoding utf8
    }
    $count = $script:Checks.Count
    $script:Checks.Clear()
    if ($failed.Count -gt 0) { throw "$Title`: $($failed.Count) of $count checks failed: $(($failed | ForEach-Object Name) -join '; ')" }
    Write-Host "$Title`: all $count checks passed or were reported only."
}

function Get-CheckMode {
    <# Reads a mode from an environment variable (enforce, report or skip); anything else means enforce. #>
    param([Parameter(Mandatory = $true)][string]$Variable)
    $value = [Environment]::GetEnvironmentVariable($Variable)
    if ($value -in 'enforce', 'report', 'skip') { $value } else { 'enforce' }
}

function Test-OpenSSHInstallation {
    <#
      Checks an installed package: product version, services, binaries, banner, firewall rule, recovery
      policy. -Port is where sshd must answer; -FirewallPort and -FirewallProfileMask (0 = all
      profiles, 1 Domain, 2 Private, 4 Public) describe the expected rule. Each of the three has its own
      mode (enforce, report, skip), so checks of features still being implemented can be relaxed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ProductVersion,
        [Parameter(Mandatory = $true)][string]$FileVersion,
        [int]$Port = 22,
        [ValidateSet('enforce', 'report', 'skip')][string]$PortMode = 'enforce',
        [string]$FirewallPort = '22',
        [ValidateSet('enforce', 'report', 'skip')][string]$FirewallPortMode = 'enforce',
        [int]$FirewallProfileMask = (Get-DefaultFirewallProfileMask),
        [ValidateSet('enforce', 'report', 'skip')][string]$FirewallProfileMode = 'enforce'
    )
    $dir = Get-OpenSSHInstallDir
    $product = Get-InstalledOpenSSHProduct
    Test-Check 'Product registered in Apps & features' ($null -ne $product) "$(if ($product) { $product.ProductCode + ' ' + $product.DisplayVersion })" | Out-Null
    if ($product) { Test-Check "Installed product version is $ProductVersion" ($product.DisplayVersion -eq $ProductVersion) $product.DisplayVersion | Out-Null }

    foreach ($name in 'sshd', 'ssh-agent') {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { Start-Sleep -Seconds 5; $svc.Refresh() }
        Test-Check "Service $name Running / Automatic" ($svc -and $svc.Status -eq 'Running' -and "$($svc.StartType)" -eq 'Automatic') "$(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'missing' })" | Out-Null
    }
    $sshdSvc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $expectedExe = Join-Path $dir 'sshd.exe'
    Test-Check 'sshd service runs the installed sshd.exe' ($sshdSvc -and $sshdSvc.PathName -and $sshdSvc.PathName.Trim('"') -like "$expectedExe*") "$(if ($sshdSvc) { $sshdSvc.PathName })" | Out-Null

    $sshdFile = Get-Item -LiteralPath $expectedExe -ErrorAction SilentlyContinue
    $fv = if ($sshdFile) { $sshdFile.VersionInfo.FileVersion } else { $null }
    Test-Check "sshd.exe file version is $FileVersion" ($fv -eq $FileVersion) "$fv" | Out-Null

    $sshV = Invoke-Native -FilePath (Join-Path $dir 'ssh.exe') -Arguments '-V'
    Test-Check 'ssh -V names OpenSSH-Server-PN' ($sshV.Output -match 'OpenSSH_for_Windows_\S+ OpenSSH-Server-PN') $sshV.Output | Out-Null

    if ($PortMode -eq 'skip') {
        Test-Check "Banner on port $Port" $true -Mode skip | Out-Null
    } else {
        $banner = Get-SshBanner -Port $Port
        Test-Check "Banner on port $Port" ($banner -match '^SSH-2\.0-OpenSSH_for_Windows_\S+ OpenSSH-Server-PN') "$banner; sshd listens on $((Get-SshdListenPort) -join ', ')" -Mode $PortMode | Out-Null
    }

    $failure = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments 'qfailure sshd'
    Test-Check 'sshd recovery policy restarts the service' ($failure.Output -match 'RESTART') ((($failure.Output -split "`r?`n" | Where-Object { $_ -match 'RESTART|RESET' }) -join '; ') -replace '\s+', ' ') | Out-Null

    $rules = @(Get-SshdFirewallRule)
    Test-Check 'Exactly one firewall rule for sshd' ($rules.Count -eq 1) "$($rules.Count) rule(s) named '$script:RuleName'" | Out-Null
    if ($rules.Count -ge 1) {
        $r = $rules[0]
        Test-Check 'Firewall rule enabled, inbound, allow, TCP, program sshd.exe' ($r.Enabled -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow' -and $r.Protocol -eq 'TCP' -and $r.Program -like '*sshd.exe') "$($r.Enabled) $($r.Direction) $($r.Action) $($r.Protocol) $($r.Program)" | Out-Null
        Test-Check "Firewall rule port $FirewallPort" ($r.LocalPort -eq $FirewallPort) "port $($r.LocalPort)" -Mode $FirewallPortMode | Out-Null
        Test-Check "Firewall rule profile mask $FirewallProfileMask" ($r.ProfileMask -eq $FirewallProfileMask) "profile $($r.Profile) ($($r.ProfileMask))" -Mode $FirewallProfileMode | Out-Null
    }
}

function Test-MsiLog {
    <# Lists the pre-install script's lines from an MSI log; warnings become annotations. #>
    param([Parameter(Mandatory = $true)][string]$LogPath, [switch]$RequirePreinstall)
    $lines = @(Select-String -LiteralPath $LogPath -Pattern 'preinstall: ' | ForEach-Object { $_.Line.Substring($_.Line.IndexOf('preinstall: ')) } | Select-Object -Unique)
    $lines | ForEach-Object { Write-Host $_ }
    foreach ($w in $lines | Where-Object { $_ -like 'preinstall: warning*' }) { Write-Annotation warning $w 'Installer warning' }
    if ($RequirePreinstall) { Test-Check 'MSI log has the pre-install step' ($lines.Count -gt 0) "$($lines.Count) line(s)" | Out-Null }
}

function Invoke-ManagerTest {
    <#
      Runs OpenSSH Server Manager in one of its unattended modes (--check, --selftest, --keytest,
      --authtest, --unittest). It is a GUI-subsystem program: wait for it and read the report it writes.
      Returns the exit code.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][ValidateSet('--check', '--selftest', '--keytest', '--authtest', '--unittest')][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ReportDir,
        [int]$TimeoutMinutes = 20
    )
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    $report = Join-Path $ReportDir ('manager' + $Mode.Substring(1) + '.txt')
    $p = Start-Process -FilePath $Exe -ArgumentList $Mode, ('"' + $report + '"') -PassThru
    $null = $p.Handle   # keeps the process handle so that ExitCode is available after the exit
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        try { $p.Kill() } catch { Write-Verbose "already exited: $_" }
        throw "OpenSSHServerManager.exe $Mode did not finish within $TimeoutMinutes minutes"
    }
    $p.WaitForExit()
    Write-Host "== OpenSSHServerManager.exe $Mode, exit code $($p.ExitCode)"
    if (Test-Path -LiteralPath $report) { Get-Content -LiteralPath $report | ForEach-Object { Write-Host $_ } } else { Write-Host "(no report at $report)" }
    if ($env:GITHUB_STEP_SUMMARY) {
        $result = if (Test-Path -LiteralPath $report) { (Select-String -LiteralPath $report -Pattern '^RESULT' | Select-Object -Last 1).Line } else { 'no report' }
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "- OpenSSH Server Manager ``$Mode``: exit code $($p.ExitCode), $result" -Encoding utf8
    }
    $p.ExitCode
}

function New-AdminTestKey {
    <#
      Creates an Ed25519 key without passphrase and authorizes it for the current account (an
      administrator) in %ProgramData%\ssh\administrators_authorized_keys, readable by SYSTEM and
      Administrators only. Returns the private key path.
    #>
    param([Parameter(Mandatory = $true)][string]$Dir)
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $key = Join-Path $Dir 'ci_ed25519'
    Remove-Item -LiteralPath $key, "$key.pub" -ErrorAction SilentlyContinue
    $gen = Invoke-Native -FilePath (Join-Path (Get-OpenSSHInstallDir) 'ssh-keygen.exe') -Arguments ('-q -t ed25519 -N "" -C ci-session-test -f "' + $key + '"')
    if ($gen.ExitCode -ne 0) { throw "ssh-keygen failed: $($gen.Output)" }
    $authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    Add-Content -LiteralPath $authorized -Value (Get-Content -LiteralPath "$key.pub") -Encoding ascii
    # SIDs, not names: Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18), whatever the Windows language.
    $acl = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\icacls.exe') -Arguments ('"' + $authorized + '" /inheritance:r /grant *S-1-5-32-544:F /grant *S-1-5-18:F')
    if ($acl.ExitCode -ne 0) { throw "icacls failed: $($acl.Output)" }
    $key
}

function Start-TestSshSession {
    <#
      Opens a key login to this server that runs for -Seconds (ping as a timer; the default shell is
      cmd.exe) and returns the ssh process once the remote command has started. Output goes to
      <Dir>\session.out.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Dir,
        [int]$Seconds = 900
    )
    $out = Join-Path $Dir 'session.out'
    $err = Join-Path $Dir 'session.err'
    $knownHosts = Join-Path $Dir 'known_hosts'
    $arguments = @(
        '-i', ('"' + $KeyPath + '"'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
        '-o', ('UserKnownHostsFile="' + $knownHosts + '"'), '-p', $Port, ($env:USERNAME + '@127.0.0.1'),
        ('"echo session-started & ping -n ' + $Seconds + ' 127.0.0.1 >nul"')
    ) -join ' '
    $p = Start-Process -FilePath (Join-Path (Get-OpenSSHInstallDir) 'ssh.exe') -ArgumentList $arguments -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) { break }
        if ((Test-Path -LiteralPath $out) -and (Select-String -LiteralPath $out -Pattern 'session-started' -Quiet)) { return $p }
        Start-Sleep -Seconds 1
    }
    $detail = if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Raw } else { '' }
    throw "The test SSH session did not start (exited: $($p.HasExited)). $detail"
}

Export-ModuleMember -Function Write-Annotation, Invoke-Native, Get-MsiInfo, New-FailingMsi, Get-MsiTableRows, Invoke-Msiexec, Get-InstalledOpenSSHProduct,
    Get-SshBanner, Get-SshdListenPort, Get-SshdFirewallRule, Get-DefaultFirewallProfileMask, Reset-Checks, Test-Check,
    Complete-Checks, Get-CheckMode, Test-OpenSSHInstallation, Test-MsiLog, Invoke-ManagerTest, New-AdminTestKey,
    Start-TestSshSession, Get-OpenSSHInstallDir
