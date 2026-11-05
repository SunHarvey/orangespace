param([string]$Directory = (Split-Path -Parent $PSScriptRoot))
# Non-executing PS5.1 parser and C# interop compilation only. No SCM/WFP/GUI IO.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($name in @('Common.ps1','Install.ps1','Start.ps1','Uninstall.ps1')) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Directory $name),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ('parse-failed:'+$name) }
    if ($name -eq 'Common.ps1') {
        $strings = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.Contains('public static class OrangeInstallNative') },$true))
        if ($strings.Count -ne 1) { throw 'interop-source-count' }
        Add-Type -TypeDefinition $strings[0].Value
        $method = [OrangeInstallNative].GetMethod('CreateServiceW')
        $expected = @('m','name','display','access','type','start','error','image','group','tag','deps','account','password')
        $actual = @($method.GetParameters() | ForEach-Object { $_.Name })
        if (($actual -join ',') -cne ($expected -join ',')) { throw 'service-api-parameters' }
        foreach ($api in @('QueryServiceConfigW','ReadStatus','SetServiceObjectSecurity','QueryServiceObjectSecurity','CreateFileW','GetFileInformationByHandle')) {
            if ($null -eq [OrangeInstallNative].GetMethod($api)) { throw 'interop-api-missing' }
        }
    }
}
Write-Output 'parse-and-interop-compile-ok; no installer/native API execution'
