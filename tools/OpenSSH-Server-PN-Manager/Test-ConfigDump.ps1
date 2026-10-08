<#
.SYNOPSIS
    Checks lossless AuthorizedKeysFile dumps against a built sshd, without host keys or services.
#>
param([Parameter(Mandatory = $true)][string]$Sshd,
      [ValidateRange(0,10000)][int]$SeededCases = 128)
$ErrorActionPreference = 'Stop'
$Sshd = (Resolve-Path -LiteralPath $Sshd).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('pn-config-dump-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$utf8 = New-Object Text.UTF8Encoding $false
$cases = @(
    @{ Name = 'disabled files'; Value = 'none'; Expected = 'none' },
    @{ Name = 'simple path'; Value = '.ssh/authorized_keys'; Expected = '.ssh/authorized_keys' },
    @{ Name = 'multiple files'; Value = '.ssh/one .ssh/two'; Expected = '.ssh/one .ssh/two' },
    @{ Name = 'spaces and tokens'; Value = '"keys dir/%u" .ssh/%%u'; Expected = '"keys dir/%u" .ssh/%%u' },
    @{ Name = 'double quote'; Value = '"keys\"quote"'; Expected = '"keys\"quote"' },
    @{ Name = 'single quote'; Value = '"keys''quote"'; Expected = '"keys''quote"' },
    @{ Name = 'Windows backslashes'; Value = '"C:\\Keys dir\\%u"'; Expected = '"C:\\Keys dir\\%u"' },
    @{ Name = 'leading comment character'; Value = '"#keys"'; Expected = '"#keys"' }
)
# Every generated path contains whitespace, requiring quotes; the independent input encoder
# produces a canonical line that must survive both native parsing and dump/reparse unchanged.
$random = New-Object Random 48771
$alphabet = @('a','Z','0','9','%','u','#','\','"',"'",'/',':','-','_', ' ', "`t")
for ($caseIndex = 0; $caseIndex -lt $SeededCases; $caseIndex++) {
    $encoded = @()
    $pathCount = $random.Next(1,5)
    for ($pathIndex = 0; $pathIndex -lt $pathCount; $pathIndex++) {
        $token = 'k '
        $length = $random.Next(1,33)
        for ($i = 0; $i -lt $length; $i++) { $token += $alphabet[$random.Next($alphabet.Count)] }
        $encoded += '"' + $token.Replace('\','\\').Replace('"','\"') + '"'
    }
    $value = $encoded -join ' '
    $cases += @{ Name = "seed 48771 case $caseIndex"; Value = $value; Expected = $value; Generated = $true }
}
try {
    foreach ($case in $cases) {
        $inputConfig = Join-Path $scratch 'input.conf'
        $roundtripConfig = Join-Path $scratch 'roundtrip.conf'
        [IO.File]::WriteAllText($inputConfig, "AuthorizedKeysFile $($case.Value)`n", $utf8)
        $dump = @(& $Sshd -G -f $inputConfig 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "$($case.Name): sshd -G failed: $dump" }
        $line = @($dump | Where-Object { "$_" -match '^AuthorizedKeysFile ' })
        if ($line.Count -ne 1) { throw "$($case.Name): expected one explicit AuthorizedKeysFile line; got $($line.Count)." }
        $expected = 'AuthorizedKeysFile ' + $case.Expected
        if ("$($line[0])".TrimEnd("`r") -cne $expected) { throw "$($case.Name): expected [$expected], received [$($line[0])]." }
        [IO.File]::WriteAllText($roundtripConfig, "$($line[0])`n", $utf8)
        $again = @(& $Sshd -G -f $roundtripConfig 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "$($case.Name): dumped line could not be parsed: $again" }
        $secondLine = @($again | Where-Object { "$_" -match '^AuthorizedKeysFile ' })
        if ($secondLine.Count -ne 1 -or "$($secondLine[0])" -cne "$($line[0])") { throw "$($case.Name): argument boundaries changed on roundtrip." }
        if (-not $case.Generated) { Write-Host "PASS $($case.Name)" }
    }
    Write-Host "All $($cases.Count) AuthorizedKeysFile dump checks passed (8 fixed, $SeededCases seeded)."
}
finally {
    $resolved = (Resolve-Path -LiteralPath $scratch).Path
    if ($resolved -ne [IO.Path]::GetFullPath($scratch)) { throw 'Unexpected scratch directory resolution; cleanup refused.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
