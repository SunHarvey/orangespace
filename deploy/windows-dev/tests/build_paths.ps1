# Exact production path-resolution block; no build, output creation or SCM.
$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '../Build.ps1') -Raw
$first = $source.IndexOf('# Freeze every caller-supplied path')
$last = $source.IndexOf('if (Test-Path -LiteralPath $BuildRoot)', $first)
if ($first -lt 0 -or $last -le $first) { throw 'Missing production path block' }
$block = $source.Substring($first, $last - $first)
$caller = Join-Path $PSScriptRoot '..'
$caller = (Get-Item -LiteralPath $caller).FullName
$processDirectory = [Environment]::CurrentDirectory
Push-Location $caller
try {
    if ([Environment]::CurrentDirectory -ne $processDirectory) { throw 'Process cwd changed unexpectedly' }
    if ($PWD.Path -eq $processDirectory) { throw 'Regression requires different process cwd and PowerShell PWD' }
    $values = & ([scriptblock]::Create('$BuildRoot="relative-build"; $Helper="relative-helper.exe"; $Output="relative-output";' + $block + '; @{BuildRoot=$BuildRoot;Helper=$Helper;Output=$Output}'))
    foreach ($pair in @(@('BuildRoot','relative-build'),@('Helper','relative-helper.exe'),@('Output','relative-output'))) {
        $expected = Join-Path $caller $pair[1]
        if ($values[$pair[0]] -cne $expected) { throw ($pair[0] + ' resolved outside actual PowerShell caller directory') }
    }
    Write-Output 'PASS exact Build path block: all three paths use actual PowerShell PWD; no build/SCM executed'
} finally { Pop-Location }
