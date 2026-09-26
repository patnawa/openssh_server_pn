<#
.SYNOPSIS
    Probes of the built OpenSSH binaries and their libcrypto.dll, each in a process of its own with a timeout,
    so that a crash or a hang in one probe cannot hide the others. Information only: the script never fails.

.DESCRIPTION
    Written when the first run of the ARM64 binaries (GitHub's windows-11-arm runner) crashed unittest-sshbuf and
    unittest-hostkeys at the first elliptic-curve operation and left unittest-kex and unittest-sshkey hanging,
    while sshd never reported itself started (it generates the host keys first). The probes tell libcrypto's
    arithmetic (BN), its elliptic curves (EC), its random numbers and the ssh-keygen key types apart:

      machine        the PE machine type of every executable and DLL (x64, x86, ARM64), and this process
      version        OpenSSL_version(0) of libcrypto.dll, as loaded by this process
      bn             BN_mul and BN_mod_exp against values computed with System.Numerics.BigInteger
      ec             EC_KEY_new_by_curve_name and EC_KEY_generate_key for P-256, P-384 and P-521
      rand           RAND_bytes
      keygen-ed25519 ssh-keygen -t ed25519 (OpenSSH's own arithmetic, libcrypto for SHA-512)
      keygen-ecdsa   ssh-keygen -t ecdsa -b 256 (libcrypto EC)
      keygen-rsa     ssh-keygen -t rsa -b 2048 (libcrypto BN, prime generation)
      fingerprint    ssh-keygen -lf of the ed25519 key
      sshd-t         sshd -t with a configuration that names the ed25519 key as host key

    The libcrypto probes run only in a process of the DLL's own architecture (P/Invoke cannot load another one).

.EXAMPLE
    ./.github/scripts/Test-CryptoProbes.ps1 -BinPath src\bin\x64\Release -Label x64
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinPath,
    [string]$Label = '',
    [int]$TimeoutSeconds = 90,
    # Internal: run one probe in this process (the parent starts a child per probe).
    [string]$Probe = '',
    [string]$WorkDir = ''
)
$ErrorActionPreference = 'Continue'
# An empty passphrase (-N '') must reach ssh-keygen as an empty argument: PowerShell 7.3 and later do that in the Windows mode.
if (Get-Variable PSNativeCommandArgumentPassing -ErrorAction SilentlyContinue) { $PSNativeCommandArgumentPassing = 'Windows' }
$BinPath = (Resolve-Path -LiteralPath $BinPath).Path

function Get-PeMachine([string]$path) {
    try {
        $fs = [IO.File]::OpenRead($path)
        try {
            $b = New-Object byte[] 64; [void]$fs.Read($b, 0, 64)
            $lfanew = [BitConverter]::ToInt32($b, 60)
            $fs.Seek($lfanew + 4, 'Begin') | Out-Null
            $m = New-Object byte[] 2; [void]$fs.Read($m, 0, 2)
            switch ([BitConverter]::ToUInt16($m, 0)) { 0x8664 { 'x64' } 0x014c { 'x86' } 0xAA64 { 'ARM64' } 0x01c4 { 'ARM' } default { ('0x{0:X4}' -f $_) } }
        } finally { $fs.Dispose() }
    } catch { "unreadable: $($_.Exception.Message)" }
}

function Get-ProcessMachine {
    $a = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $a = "$a (WOW64 on $env:PROCESSOR_ARCHITEW6432)" }
    if (-not [Environment]::Is64BitProcess) { return "x86 process on $a" }
    switch -Regex ($a) { 'ARM64' { 'ARM64 process' } 'AMD64' { 'x64 process' } default { "$a process" } }
}

# ---- one probe, in this process -------------------------------------------------------------------------------
if ($Probe) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $env:PATH = "$BinPath;$env:PATH"
    if ($Probe -in 'version', 'bn', 'ec', 'rand') {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class LC {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr LoadLibrary(string path);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr OpenSSL_version(int t);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr BN_new();
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr BN_CTX_new();
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int BN_dec2bn(ref IntPtr a, string s);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr BN_bn2dec(IntPtr a);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int BN_mul(IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int BN_mod_exp(IntPtr r, IntPtr a, IntPtr p, IntPtr m, IntPtr ctx);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int BN_num_bits(IntPtr a);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr EC_KEY_new_by_curve_name(int nid);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int EC_KEY_generate_key(IntPtr key);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int EC_KEY_check_key(IntPtr key);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern int RAND_bytes(byte[] buf, int num);
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern uint ERR_get_error();
    [DllImport("libcrypto.dll", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr ERR_error_string(uint e, IntPtr buf);
}
"@
        $dll = Join-Path $BinPath 'libcrypto.dll'
        $h = [LC]::LoadLibrary($dll)
        if ($h -eq [IntPtr]::Zero) { Write-Output "could not load $dll (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())) from a $(Get-ProcessMachine)"; exit 2 }
        function Get-LastLibcryptoError { $e = [LC]::ERR_get_error(); if ($e -eq 0) { 'no libcrypto error queued' } else { [Runtime.InteropServices.Marshal]::PtrToStringAnsi([LC]::ERR_error_string($e, [IntPtr]::Zero)) } }
    }
    switch ($Probe) {
        'version' {
            Write-Output ("libcrypto: " + [Runtime.InteropServices.Marshal]::PtrToStringAnsi([LC]::OpenSSL_version(0)) + " in a $(Get-ProcessMachine)")
            exit 0
        }
        'bn' {
            $ctx = [LC]::BN_CTX_new()
            $cases = @(
                @{ Name = 'BN_mul 123456789 * 987654321'; Op = 'mul'; A = '123456789'; B = '987654321' },
                @{ Name = 'BN_mul 2^200 * (2^200+1)'; Op = 'mul'; A = [Numerics.BigInteger]::Pow(2, 200).ToString(); B = ([Numerics.BigInteger]::Pow(2, 200) + 1).ToString() },
                @{ Name = 'BN_mod_exp 3^200 mod 1000003'; Op = 'modexp'; A = '3'; B = '200'; M = '1000003' },
                @{ Name = 'BN_mod_exp 7^(2^70) mod (2^127-1)'; Op = 'modexp'; A = '7'; B = [Numerics.BigInteger]::Pow(2, 70).ToString(); M = ([Numerics.BigInteger]::Pow(2, 127) - 1).ToString() }
            )
            $bad = 0
            foreach ($c in $cases) {
                $a = [IntPtr]::Zero; $b = [IntPtr]::Zero; $m = [IntPtr]::Zero; $r = [LC]::BN_new()
                [void][LC]::BN_dec2bn([ref]$a, $c.A); [void][LC]::BN_dec2bn([ref]$b, $c.B)
                if ($c.Op -eq 'mul') {
                    $ok = [LC]::BN_mul($r, $a, $b, $ctx)
                    $expected = ([Numerics.BigInteger]::Parse($c.A) * [Numerics.BigInteger]::Parse($c.B)).ToString()
                } else {
                    [void][LC]::BN_dec2bn([ref]$m, $c.M)
                    $ok = [LC]::BN_mod_exp($r, $a, $b, $m, $ctx)
                    $expected = [Numerics.BigInteger]::ModPow([Numerics.BigInteger]::Parse($c.A), [Numerics.BigInteger]::Parse($c.B), [Numerics.BigInteger]::Parse($c.M)).ToString()
                }
                $got = if ($ok -eq 1) { [Runtime.InteropServices.Marshal]::PtrToStringAnsi([LC]::BN_bn2dec($r)) } else { "call returned $ok ($(Get-LastLibcryptoError))" }
                $same = ($got -eq $expected)
                if (-not $same) { $bad++ }
                Write-Output ("{0}: {1}  got {2}{3}" -f $c.Name, $(if ($same) { 'ok' } else { 'WRONG' }), $(if ($got.Length -gt 60) { $got.Substring(0, 60) + '...' } else { $got }), $(if ($same) { '' } else { "  expected $expected" }))
            }
            exit $(if ($bad -eq 0) { 0 } else { 1 })
        }
        'ec' {
            $bad = 0
            foreach ($curve in @(@{ Nid = 415; Name = 'P-256 (prime256v1)' }, @{ Nid = 715; Name = 'P-384 (secp384r1)' }, @{ Nid = 716; Name = 'P-521 (secp521r1)' })) {
                $k = [LC]::EC_KEY_new_by_curve_name($curve.Nid)
                if ($k -eq [IntPtr]::Zero) { Write-Output "$($curve.Name): EC_KEY_new_by_curve_name returned NULL ($(Get-LastLibcryptoError))"; $bad++; continue }
                $g = [LC]::EC_KEY_generate_key($k)
                $chk = if ($g -eq 1) { [LC]::EC_KEY_check_key($k) } else { -1 }
                Write-Output ("{0}: key created; generate_key {1}; check_key {2}{3}" -f $curve.Name, $g, $chk, $(if ($g -ne 1 -or $chk -ne 1) { " ($(Get-LastLibcryptoError))" } else { '' }))
                if ($g -ne 1 -or $chk -ne 1) { $bad++ }
            }
            exit $(if ($bad -eq 0) { 0 } else { 1 })
        }
        'rand' {
            $buf = New-Object byte[] 32
            $r = [LC]::RAND_bytes($buf, 32)
            Write-Output ("RAND_bytes returned {0}: {1}" -f $r, (($buf | ForEach-Object { $_.ToString('x2') }) -join ''))
            exit $(if ($r -eq 1) { 0 } else { 1 })
        }
        'keygen-ed25519' { & (Join-Path $BinPath 'ssh-keygen.exe') -q -t ed25519 -N '' -C probe -f (Join-Path $WorkDir 'k_ed25519') 2>&1; exit $LASTEXITCODE }
        'keygen-ecdsa' { & (Join-Path $BinPath 'ssh-keygen.exe') -q -t ecdsa -b 256 -N '' -C probe -f (Join-Path $WorkDir 'k_ecdsa') 2>&1; exit $LASTEXITCODE }
        'keygen-rsa' { & (Join-Path $BinPath 'ssh-keygen.exe') -q -t rsa -b 2048 -N '' -C probe -f (Join-Path $WorkDir 'k_rsa') 2>&1; exit $LASTEXITCODE }
        'fingerprint' { & (Join-Path $BinPath 'ssh-keygen.exe') -lf (Join-Path $WorkDir 'k_ed25519.pub') 2>&1; exit $LASTEXITCODE }
        'sshd-t' {
            $cfg = Join-Path $WorkDir 'sshd_config'
            "HostKey " + (Join-Path $WorkDir 'k_ed25519').Replace('\', '/') + "`nPort 47999`n" | Set-Content -LiteralPath $cfg -Encoding ascii
            & (Join-Path $BinPath 'sshd.exe') -t -f $cfg 2>&1; exit $LASTEXITCODE
        }
        default { Write-Output "unknown probe $Probe"; exit 2 }
    }
}

# ---- the parent: machine types, then one child per probe ------------------------------------------------------
$title = "Crypto probes $Label ($BinPath)"
Write-Host "== $title"
Write-Host "This process: $(Get-ProcessMachine)"
$files = @(Get-ChildItem -LiteralPath $BinPath -File | Where-Object { $_.Extension -in '.exe', '.dll' } | Sort-Object Name)
$machines = @{}
foreach ($f in $files) { $machines[$f.Name] = Get-PeMachine $f.FullName }
$grouped = $machines.GetEnumerator() | Group-Object Value | ForEach-Object { "$($_.Name): $(($_.Group | ForEach-Object Name | Sort-Object) -join ', ')" }
$grouped | ForEach-Object { Write-Host "  $_" }
$processIs = switch -Regex (Get-ProcessMachine) { '^ARM64' { 'ARM64' } '^x64' { 'x64' } '^x86' { 'x86' } default { '?' } }
$dllMachine = $machines['libcrypto.dll']
$canLoad = ($dllMachine -eq $processIs)
if (-not $canLoad) { Write-Host "libcrypto.dll is $dllMachine and this is a $processIs process: the libcrypto probes are skipped (the ssh-keygen and sshd probes still run)" }

$work = if ($WorkDir) { $WorkDir } else { Join-Path ([IO.Path]::GetTempPath()) ("crypto-probes-" + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
New-Item -ItemType Directory -Force -Path $work | Out-Null
$self = $PSCommandPath
$host7 = (Get-Process -Id $PID).Path   # the same PowerShell as this one (pwsh or powershell)
$probes = @()
if ($canLoad) { $probes += 'version', 'bn', 'ec', 'rand' }
$probes += 'keygen-ed25519', 'keygen-ecdsa', 'keygen-rsa', 'fingerprint', 'sshd-t'
$results = @()
foreach ($p in $probes) {
    $out = Join-Path $work "$p.out.txt"; $err = Join-Path $work "$p.err.txt"
    $timeout = if ($p -eq 'keygen-rsa') { $TimeoutSeconds * 2 } else { $TimeoutSeconds }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $host7 -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"'), '-BinPath', ('"' + $BinPath + '"'), '-Probe', $p, '-WorkDir', ('"' + $work + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $proc.Handle
    $finished = $proc.WaitForExit($timeout * 1000)
    if (-not $finished) { try { $proc.Kill() } catch { Write-Verbose "already exited: $_" }; $proc.WaitForExit() }
    $text = @(); foreach ($f in $out, $err) { if (Test-Path -LiteralPath $f) { $text += Get-Content -LiteralPath $f | Where-Object { $_ -ne '' } } }
    $code = if ($finished) { $proc.ExitCode } else { $null }
    $status = if (-not $finished) { "HUNG (killed after $timeout s)" } elseif ($code -eq 0) { 'ok' } elseif ($code -lt 0 -or $code -gt 255) { ('CRASHED (0x{0:X8})' -f [uint32]$code) } else { "failed (exit $code)" }
    $line = "{0,-15} {1,-28} {2,7:0.0} s  {3}" -f $p, $status, $sw.Elapsed.TotalSeconds, (($text | Select-Object -First 4) -join ' | ')
    Write-Host $line
    $results += [pscustomobject]@{ Probe = $p; Status = $status; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Output = ($text -join ' | ') }
}
if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @("#### $title", '', "This process: $(Get-ProcessMachine). Binaries: $($grouped -join '; ')", '', '| Probe | Result | Seconds | Output |', '|---|---|---|---|')
    foreach ($r in $results) { $lines += "| $($r.Probe) | $($r.Status) | $($r.Seconds) | $(($r.Output -replace '\|', '/').Substring(0, [Math]::Min(300, $r.Output.Length))) |" }
    $lines += ''
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $lines -Encoding utf8
}
$notOk = @($results | Where-Object { $_.Status -ne 'ok' })
if ($notOk.Count -gt 0 -and $env:GITHUB_ACTIONS -eq 'true') { Write-Host "::warning title=Crypto probes $Label::$($notOk.Count) of $($results.Count) probes did not pass: $(($notOk | ForEach-Object { "$($_.Probe) $($_.Status)" }) -join '; ')" }
exit 0
