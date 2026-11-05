# Local Linux PowerShell injected production-policy tests; NO Windows/SCM execution.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Common.ps1')
$base = Join-Path ([IO.Path]::GetTempPath()) ('os-policy-' + [guid]::NewGuid())
New-Item -ItemType Directory $base | Out-Null
function Expect-Reject($Body, $Message) {
    try { & $Body } catch { if ($_.Exception.Message -like "*$Message*") { return }; throw }
    throw "Expected rejection: $Message"
}
try {
    foreach ($name in $script:Names) { [IO.File]::WriteAllText((Join-Path $base $name), 'MZ-policy') }
    $script:HelperHash = (Get-FileHash (Join-Path $base 'sing-box.exe')).Hash.ToLowerInvariant()
    $rows = @($script:Names | ForEach-Object { @{name=$_; size=9; sha256=$script:HelperHash} })
    @{schema=1;kind='orangespace-windows-dev';files=$rows} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $base 'manifest.json')
    # Inject only the OS ACL boundary; execute the real manifest caller.
    $script:blocked = $base
    function Assert-Protected([string]$Path, [bool]$Private = $false) { if ($Path -ceq $script:blocked) { throw 'injected unprotected' } }
    foreach ($name in @('') + @('manifest.json') + $script:Names) {
        $script:blocked = if ($name) { Join-Path $base $name } else { $base }
        Expect-Reject { Get-Manifest $base } 'injected unprotected'
    }
    $script:blocked = ''
    $snapshot = Get-Manifest $base
    [IO.File]::WriteAllText((Join-Path $base 'OrangeSpaceService.exe'), 'MZ-changed')
    $rows[2].sha256 = (Get-FileHash (Join-Path $base 'OrangeSpaceService.exe')).Hash.ToLowerInvariant()
    $rows[2].size = 10
    @{schema=1;kind='orangespace-windows-dev';files=$rows} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $base 'manifest.json')
    Expect-Reject { Get-Manifest $base $true $snapshot } 'snapshot'
    # Real Build caller with inert command seams: relative Helper/Output must freeze.
    $build = Get-Content (Join-Path $PSScriptRoot '../Build.ps1') -Raw
    $build = $build.Replace(". (Join-Path `$PSScriptRoot 'Common.ps1')", '')
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    $build = $build.Replace("`$repo = (Resolve-Path (Join-Path `$PSScriptRoot '../..')).Path", "`$repo = '$repo'")
    $script:expectedHelper = [IO.Path]::GetFullPath('relative-helper.exe')
    function Assert-Ordinary($Path) { if ($Path -cne $script:expectedHelper) { throw 'relative helper not frozen' } }
    function Get-FileHash($LiteralPath) { throw 'build-frozen-check-reached' }
    $env:OS = 'Windows_NT'
    Expect-Reject { & ([scriptblock]::Create($build)) -BuildRoot (Join-Path $base 'fresh') -Helper relative-helper.exe -Output relative-output } 'build-frozen-check-reached'
    Write-Output 'PASS manifest protected-source caller, frozen snapshot, Build absolute-helper caller (injected Linux policy only)'
} finally { Remove-Item -LiteralPath $base -Recurse -Force }
