<#
.SYNOPSIS
    One installer scenario of the install tests in .github/workflows/openssh.yml.

.DESCRIPTION
    The scenarios run in this order on one machine; each starts from the state the previous one left:

    | Scenario  | Does                                                                                   |
    |-----------|----------------------------------------------------------------------------------------|
    | Install   | installs the release MSI; checks services, version, banner on 22, firewall defaults    |
    | Upgrade   | sets the firewall rule to port 2222 and Private only, installs the upgrade-test MSI    |
    |           | (third version field + 1), checks that the rule kept both                              |
    | Repair    | msiexec /fa of the installed package; the rule still has port 2222 and Private         |
    | Rollback  | a copy of the release MSI that fails after StartServices (New-FailingMsi) is installed  |
    |           | with ALLOWDOWNGRADE=1: msiexec returns 1603, the previous package is back with its      |
    |           | services and files, the rule has port 2222 and Private again, the saved record is gone |
    | Downgrade | the older release MSI is refused (1603) without ALLOWDOWNGRADE; then installed with    |
    |           | ALLOWDOWNGRADE=1 SSHD_PORT=2200: sshd answers on 2200, the rule has port 2200 and      |
    |           | still Private only                                                                     |
    | Sessions  | opens a key login, installs the upgrade-test MSI with ACTIVE_SESSIONS=abort (refused,  |
    |           | session alive) and ACTIVE_SESSIONS=close (installed, session ended)                   |
    | Uninstall | msiexec /x; services, rule and program files gone, %ProgramData%\ssh kept              |

    ADJUST: firewall preservation, SSHD_PORT and ACTIVE_SESSIONS are being implemented in the
    installer in parallel with this workflow. Their checks follow the modes in the environment
    variables FIREWALL_PRESERVATION_CHECK, SSHD_PORT_CHECK and ACTIVE_SESSIONS_CHECK (enforce, report,
    skip; set in the workflow), and the expected values are the constants below. Adjust both when
    the behaviour of those features is final.

    Needs an elevated PowerShell 7. It changes the machine (installs services, firewall rules, keys):
    run it on a disposable test machine only.

.EXAMPLE
    ./.github/scripts/Test-Installer.ps1 -Scenario Install -MsiDir C:\msi -Msi OpenSSH-Win64-v10.5.1.0.msi -UpgradeMsi OpenSSH-Win64-v10.5.2.0-upgradetest.msi -Version 10.5.1.0 -UpgradeVersion 10.5.2.0 -LogDir C:\logs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Upgrade', 'Repair', 'Rollback', 'Downgrade', 'Sessions', 'Uninstall')][string]$Scenario,
    [string]$MsiDir = $env:MSI_DIR,
    [string]$Msi = $env:MSI,
    [string]$UpgradeMsi = $env:UPGRADE_MSI,
    [string]$Version = $env:VERSION,
    [string]$UpgradeVersion = $env:UPGRADE_VERSION,
    [string]$LogDir = $env:LOG_DIR
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'OpenSSHCI.psm1') -Force

# ---- ADJUST: values the scenarios set and expect ----------------------------------------------------------
$CustomFirewallPort = '2222'        # set on the rule before the upgrade; upgrade and repair must keep it
$CustomFirewallProfileMask = 2      # Private only (1 Domain, 2 Private, 4 Public, 0 all)
$SshdPortValue = 2200               # SSHD_PORT=<n> given to the downgrade install
$AbortExitCodes = @(1602, 1603)     # what msiexec may return when ACTIVE_SESSIONS=abort refuses the install
# -----------------------------------------------------------------------------------------------------------

foreach ($name in 'MsiDir', 'Msi', 'UpgradeMsi', 'Version', 'UpgradeVersion', 'LogDir') {
    if (-not (Get-Variable -Name $name -ValueOnly)) { throw "-$name (or its environment variable) is required" }
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$releaseMsi = Join-Path $MsiDir $Msi
$upgradeMsiPath = Join-Path $MsiDir $UpgradeMsi
$preservation = Get-CheckMode FIREWALL_PRESERVATION_CHECK
$sshdPortMode = Get-CheckMode SSHD_PORT_CHECK
$sessionsMode = Get-CheckMode ACTIVE_SESSIONS_CHECK
Write-Host "Scenario $Scenario; FIREWALL_PRESERVATION_CHECK=$preservation SSHD_PORT_CHECK=$sshdPortMode ACTIVE_SESSIONS_CHECK=$sessionsMode"

function Q([string]$Path) { '"' + $Path + '"' }

function Invoke-Install([string[]]$Arguments, [string]$Log, [int[]]$Allowed = @(0, 3010)) {
    $code = Invoke-Msiexec -Arguments $Arguments -LogPath (Join-Path $LogDir $Log) -AllowedExitCodes $Allowed
    if ($code -eq 3010) { Write-Annotation warning "msiexec $($Arguments[0]) returned 3010 (restart required)" 'Restart required' }
    $code
}

function Get-InstalledMsiPath {
    $p = Get-InstalledOpenSSHProduct
    if (-not $p) { throw 'OpenSSH Server PN is not installed; an earlier scenario failed.' }
    if ($p.DisplayVersion -eq $UpgradeVersion) { $upgradeMsiPath } else { $releaseMsi }
}

switch ($Scenario) {
    'Install' {
        foreach ($f in $releaseMsi, $upgradeMsiPath) { Get-MsiInfo $f | Format-List | Out-String | Write-Host }
        Invoke-Install @('/i', (Q $releaseMsi)) '1-install.log' | Out-Null
        Test-MsiLog (Join-Path $LogDir '1-install.log') -RequirePreinstall
        Test-OpenSSHInstallation -ProductVersion $Version -FileVersion $Version
        Complete-Checks 'Install'
    }

    'Upgrade' {
        # An administrator changed the rule: another port, Private networks only. ADJUST (firewall preservation)
        Set-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' -LocalPort $CustomFirewallPort -Profile Private
        Get-SshdFirewallRule | Format-List | Out-String | Write-Host
        Invoke-Install @('/i', (Q $upgradeMsiPath)) '2-upgrade.log' | Out-Null
        Test-MsiLog (Join-Path $LogDir '2-upgrade.log') -RequirePreinstall
        Test-OpenSSHInstallation -ProductVersion $UpgradeVersion -FileVersion $Version `
            -FirewallPort $CustomFirewallPort -FirewallPortMode $preservation `
            -FirewallProfileMask $CustomFirewallProfileMask -FirewallProfileMode $preservation
        Complete-Checks 'Upgrade keeps the firewall settings'
    }

    'Repair' {
        $msi = Get-InstalledMsiPath
        $installed = (Get-InstalledOpenSSHProduct).DisplayVersion
        Invoke-Install @('/fa', (Q $msi)) '3-repair.log' | Out-Null
        Test-MsiLog (Join-Path $LogDir '3-repair.log') -RequirePreinstall
        # ADJUST (firewall preservation): the repair recreates the rule; it must keep port and profiles.
        Test-OpenSSHInstallation -ProductVersion $installed -FileVersion $Version `
            -FirewallPort $CustomFirewallPort -FirewallPortMode $preservation `
            -FirewallProfileMask $CustomFirewallProfileMask -FirewallProfileMode $preservation
        Complete-Checks 'Repair'
    }

    'Rollback' {
        # A failed installation must leave the previous package as it was, its firewall settings included (the
        # rollback action of the firewall record). The installed package is the upgrade-test build with the rule at
        # 2222/Private; a copy of the release MSI that fails after StartServices replaces it and is rolled back.
        $before = (Get-InstalledOpenSSHProduct).DisplayVersion
        $failing = New-FailingMsi -Source $releaseMsi -Destination (Join-Path $LogDir 'rollback-test.msi')
        $rows = @(Get-MsiTableRows -Path $failing -Table 'InstallExecuteSequence' -Columns 'Action', 'Sequence' | Where-Object { $_.Action -in 'StartServices', 'CITestFailAfterStart', 'InstallFinalize' })
        Write-Host ("failing package: " + (($rows | ForEach-Object { "$($_.Action)=$($_.Sequence)" }) -join ' '))
        $code = Invoke-Install @('/i', (Q $failing), 'ALLOWDOWNGRADE=1') '3b-rollback.log' -Allowed @(0, 1603, 3010)
        Test-MsiLog (Join-Path $LogDir '3b-rollback.log')
        Test-Check 'The failing package is rolled back (msiexec exit 1603)' ($code -eq 1603) "exit code $code" | Out-Null
        if ($code -ne 1603) {
            # Nothing to roll back: put the state the next scenarios expect back (the upgrade-test build, the rule at 2222/Private).
            Write-Host 'The failing package installed; restoring the upgrade-test build for the next scenarios.'
            Invoke-Install @('/i', (Q $upgradeMsiPath)) '3c-rollback-recover.log' | Out-Null
            Set-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)' -LocalPort $CustomFirewallPort -Profile Private
            Complete-Checks 'Rollback of a failed installation'
            return
        }
        $log = Get-Content -LiteralPath (Join-Path $LogDir '3b-rollback.log') -Raw
        Test-Check 'MSI log shows the forced failure (CITestFailAfterStart)' ($log -match 'CITestFailAfterStart') | Out-Null
        Test-Check 'MSI log shows the firewall settings put back by the rollback action' ($log -match "preinstall: rollback: firewall rule '[^']+' set back to") -Mode $preservation | Out-Null
        $product = Get-InstalledOpenSSHProduct
        Test-Check "Previous package $before registered again" ($product -and $product.DisplayVersion -eq $before) "$(if ($product) { $product.DisplayVersion } else { 'nothing installed' })" | Out-Null
        foreach ($name in 'sshd', 'ssh-agent') {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            Test-Check "Service $name registered again" ($null -ne $svc) "$(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'missing' })" | Out-Null
        }
        $exe = Join-Path (Get-OpenSSHInstallDir) 'sshd.exe'
        Test-Check 'sshd.exe present again' (Test-Path -LiteralPath $exe) "$(if (Test-Path -LiteralPath $exe) { (Get-Item -LiteralPath $exe).VersionInfo.FileVersion })" | Out-Null
        $record = Get-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH\Installer' -Name FirewallRule -ErrorAction SilentlyContinue
        Test-Check 'Saved firewall record removed after the rollback' ($null -eq $record) "$(if ($record) { $record.FirewallRule })" -Mode $preservation | Out-Null
        $rules = @(Get-SshdFirewallRule)
        Test-Check 'Exactly one firewall rule for sshd after the rollback' ($rules.Count -eq 1) "$($rules.Count) rule(s)" | Out-Null
        if ($rules.Count -ge 1) {
            Test-Check "Firewall rule port $CustomFirewallPort after the rollback" ($rules[0].LocalPort -eq $CustomFirewallPort) "port $($rules[0].LocalPort)" -Mode $preservation | Out-Null
            Test-Check "Firewall rule profile mask $CustomFirewallProfileMask after the rollback" ($rules[0].ProfileMask -eq $CustomFirewallProfileMask) "profile $($rules[0].Profile) ($($rules[0].ProfileMask))" -Mode $preservation | Out-Null
            Test-Check 'Firewall rule enabled after the rollback' $rules[0].Enabled | Out-Null
        }
        # The rollback registers the services again but does not start them; the next scenarios need sshd running.
        foreach ($name in 'sshd', 'ssh-agent') {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Running') { Start-Service -Name $name }
        }
        $banner = Get-SshBanner -Port 22
        Test-Check 'sshd answers on port 22 after the rollback' ($banner -match '^SSH-2\.0-OpenSSH_for_Windows_\S+ OpenSSH-Server-PN') "$banner; sshd listens on $((Get-SshdListenPort) -join ', ')" | Out-Null
        Complete-Checks 'Rollback of a failed installation'
    }

    'Downgrade' {
        $before = (Get-InstalledOpenSSHProduct).DisplayVersion
        # 1. The older package is refused without ALLOWDOWNGRADE (launch condition), nothing changes.
        $code = Invoke-Install @('/i', (Q $releaseMsi)) '4-downgrade-refused.log' -Allowed @(0, 1603, 3010)
        Test-Check 'Older package refused without ALLOWDOWNGRADE (exit 1603)' ($code -eq 1603) "exit code $code" | Out-Null
        Test-Check "Installed version unchanged ($before)" ((Get-InstalledOpenSSHProduct).DisplayVersion -eq $before) | Out-Null
        Test-Check 'sshd still running' ((Get-Service sshd).Status -eq 'Running') | Out-Null
        Complete-Checks 'Downgrade refused'

        # 2. ALLOWDOWNGRADE=1, with SSHD_PORT (ADJUST: new property). Expected: sshd listens on SSHD_PORT, the rule
        #    gets that port, and the profiles set before the upgrade (Private) are still kept.
        $arguments = @('/i', (Q $releaseMsi), 'ALLOWDOWNGRADE=1')
        if ($sshdPortMode -ne 'skip') { $arguments += "SSHD_PORT=$SshdPortValue" }
        Invoke-Install $arguments '5-downgrade.log' | Out-Null
        Test-MsiLog (Join-Path $LogDir '5-downgrade.log') -RequirePreinstall
        if ($sshdPortMode -ne 'skip') {
            Test-OpenSSHInstallation -ProductVersion $Version -FileVersion $Version `
                -Port $SshdPortValue -PortMode $sshdPortMode `
                -FirewallPort ([string]$SshdPortValue) -FirewallPortMode $sshdPortMode `
                -FirewallProfileMask $CustomFirewallProfileMask -FirewallProfileMode $preservation
            $config = Join-Path $env:ProgramData 'ssh\sshd_config'
            $portLines = if (Test-Path -LiteralPath $config) { @(Select-String -LiteralPath $config -Pattern '^\s*Port\s+\d+' | ForEach-Object { $_.Line.Trim() }) } else { @() }
            Test-Check "sshd_config sets Port $SshdPortValue" ($portLines -contains "Port $SshdPortValue") ($portLines -join '; ') -Mode $sshdPortMode | Out-Null
        } else {
            Test-OpenSSHInstallation -ProductVersion $Version -FileVersion $Version `
                -FirewallPort $CustomFirewallPort -FirewallPortMode $preservation `
                -FirewallProfileMask $CustomFirewallProfileMask -FirewallProfileMode $preservation
        }
        Complete-Checks 'Downgrade with ALLOWDOWNGRADE=1 and SSHD_PORT'
    }

    'Sessions' {
        # ADJUST (ACTIVE_SESSIONS): abort = refuse the install while sessions are open; close = end them and install.
        if ($sessionsMode -eq 'skip') { Write-Host 'ACTIVE_SESSIONS_CHECK=skip'; return }
        $dir = Join-Path $LogDir 'session'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
        $savedKeys = if (Test-Path -LiteralPath $authorized) { [IO.File]::ReadAllBytes($authorized) } else { $null }
        $port = @(Get-SshdListenPort) | Select-Object -First 1
        if (-not $port) { throw 'sshd does not listen on any port' }
        $session = $null
        try {
            $key = New-AdminTestKey -Dir $dir
            $session = Start-TestSshSession -KeyPath $key -Port $port -Dir $dir
            $before = (Get-InstalledOpenSSHProduct).DisplayVersion
            Write-Host "Session open (ssh PID $($session.Id)) on port $port; installed $before"

            $code = Invoke-Install @('/i', (Q $upgradeMsiPath), 'ACTIVE_SESSIONS=abort') '6-sessions-abort.log' -Allowed (@(0, 3010) + $AbortExitCodes)
            Test-Check 'ACTIVE_SESSIONS=abort refuses the install while a session is open' ($code -in $AbortExitCodes) "exit code $code" -Mode $sessionsMode | Out-Null
            Test-Check 'ACTIVE_SESSIONS=abort leaves the session connected' (-not $session.HasExited) -Mode $sessionsMode | Out-Null
            Test-Check "ACTIVE_SESSIONS=abort leaves $before installed" ((Get-InstalledOpenSSHProduct).DisplayVersion -eq $before) -Mode $sessionsMode | Out-Null

            if ((Get-InstalledOpenSSHProduct).DisplayVersion -eq $UpgradeVersion) {
                Write-Host 'The upgrade went through already; the close case cannot be tested.'
                Test-Check 'ACTIVE_SESSIONS=close ends the session and installs' $false 'not run: the abort case installed the package' -Mode $sessionsMode | Out-Null
            } else {
                if ($session.HasExited) { $session = Start-TestSshSession -KeyPath $key -Port $port -Dir $dir }
                $code = Invoke-Install @('/i', (Q $upgradeMsiPath), 'ACTIVE_SESSIONS=close') '7-sessions-close.log'
                $ended = $session.WaitForExit(60000)
                Test-Check 'ACTIVE_SESSIONS=close installs the package' ($code -in 0, 3010) "exit code $code" -Mode $sessionsMode | Out-Null
                Test-Check 'ACTIVE_SESSIONS=close ends the open session' $ended -Mode $sessionsMode | Out-Null
                Test-Check "ACTIVE_SESSIONS=close: $UpgradeVersion installed" ((Get-InstalledOpenSSHProduct).DisplayVersion -eq $UpgradeVersion) -Mode $sessionsMode | Out-Null
            }
            Test-Check 'sshd running after the session tests' ((Get-Service sshd).Status -eq 'Running') | Out-Null
        } finally {
            if ($session -and -not $session.HasExited) { try { $session.Kill() } catch { Write-Verbose "already exited: $_" } }
            if ($null -ne $savedKeys) { [IO.File]::WriteAllBytes($authorized, $savedKeys) } else { Remove-Item -LiteralPath $authorized -ErrorAction SilentlyContinue }
        }
        Complete-Checks 'Active sessions'
    }

    'Uninstall' {
        $product = Get-InstalledOpenSSHProduct
        if (-not $product) { throw 'Nothing to uninstall: OpenSSH Server PN is not installed.' }
        Invoke-Install @('/x', $product.ProductCode) '8-uninstall.log' | Out-Null
        $dir = Get-OpenSSHInstallDir
        Test-Check 'Product removed from Apps & features' ($null -eq (Get-InstalledOpenSSHProduct)) | Out-Null
        Test-Check 'Service sshd removed' ($null -eq (Get-Service sshd -ErrorAction SilentlyContinue)) | Out-Null
        Test-Check 'Service ssh-agent removed' ($null -eq (Get-Service ssh-agent -ErrorAction SilentlyContinue)) -Mode report | Out-Null
        Test-Check 'Firewall rule removed' (@(Get-SshdFirewallRule).Count -eq 0) | Out-Null
        Test-Check 'Program files removed' (-not (Test-Path -LiteralPath (Join-Path $dir 'sshd.exe'))) | Out-Null
        Test-Check '%ProgramData%\ssh kept (configuration and host keys)' (Test-Path -LiteralPath (Join-Path $env:ProgramData 'ssh\sshd_config')) | Out-Null
        Complete-Checks 'Uninstall'
    }
}
