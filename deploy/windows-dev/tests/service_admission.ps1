# Local production Service caller admission tests, all OS/SCM boundaries inert.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../Common.ps1')
$exactReadService = (Get-Command Read-Service).ScriptBlock
function Reject($Body,$message) { try { & $Body } catch { if ($_.Exception.Message -like "*$message*") { return }; throw }; throw "Expected rejection: $message" }
function Assert-Admin {}
function Invoke-CimMethod { throw 'FORBIDDEN SCM mutation reached' }
Reject { Get-Target '../elsewhere' } 'Invalid fixed'
$caller=(Get-Content (Join-Path $PSScriptRoot '../Service.ps1') -Raw).Replace(". (Join-Path `$PSScriptRoot 'Common.ps1')",'')
function Get-Target($Leaf) { return '/inert-protected-root' }
$script:exists=$true
function Test-Path { return $script:exists }
function Read-Service { return [pscustomobject]@{Name='collision'} }
Reject { & ([scriptblock]::Create($caller)) -Action install -Leaf OrangeSpace-Dev-test } 'Existing target'
$script:exists=$false
# A validated source manifest chooses identity before the collision query.
function Get-Manifest { $script:ServiceName='OrangeSpaceFoundation'; return @{} }
Reject { & ([scriptblock]::Create($caller)) -Action install -Leaf OrangeSpace-Dev-test -Package model-package -ProtectedConfig model-config } 'Existing project Service'
# Actual Assert-Installed verifies every exact SCM field after inert file checks.
function Assert-Protected {}
function Get-Manifest { return @{} }
$script:modelImage='"'+(Join-Path '/inert-protected-root' 'OrangeSpaceService.exe')+'"'
$script:marker=@{kind='orangespace-windows-dev-install-v1';root='/inert-protected-root';service='OrangeSpaceFoundation';image=$script:modelImage;manifestHash='frozen';configHashes=@{'platform.json'='frozen';'nodes.json'='frozen'}} | ConvertTo-Json
# JSON Utility autoload may export Get-FileHash on Windows PowerShell 5.1;
# install the inert override only after that module has been loaded above.
function Get-FileHash { return [pscustomobject]@{Hash='frozen'} }
function Get-Content { return $script:marker }
$script:service=@{Name='OrangeSpaceFoundation';PathName=$script:modelImage;StartName='LocalSystem';ServiceType='Own Process';StartMode='Manual'}
function Read-Service { return [pscustomobject]$script:service }
$null=Assert-Installed '/inert-protected-root'
foreach ($field in @('Name','PathName','StartName','ServiceType','StartMode')) {
    $old=$script:service[$field]; $script:service[$field]='wrong'
    Reject { Assert-Installed '/inert-protected-root' } 'SCM identity'
    $script:service[$field]=$old
}
# A custom installed marker may manage only its exact project namespace.
$script:ServiceName='OrangeSpaceFoundation.Dev.p1'
$customMarker=$script:marker | ConvertFrom-Json
$customMarker.service=$script:ServiceName
$script:marker=$customMarker | ConvertTo-Json
Reject { Assert-Installed '/inert-protected-root' } 'SCM identity'
$script:service.Name=$script:ServiceName
$null=Assert-Installed '/inert-protected-root'
$customMarker.service='OrangeSpaceFoundation'
$script:marker=$customMarker | ConvertTo-Json
Reject { Assert-Installed '/inert-protected-root' } 'Installation marker mismatch'
$script:queryCount=0
function Get-CimInstance {
    param([string]$ClassName,[string]$Filter)
    if ($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='OrangeSpaceFoundation.Dev.p1'") { throw 'Original Foundation or unrelated service queried' }
    ++$script:queryCount
    return [pscustomobject]$script:service
}
$observed=& $exactReadService
if ($observed.Name -cne 'OrangeSpaceFoundation.Dev.p1' -or $script:queryCount -ne 1) { throw 'Scoped service query failed' }
$script:ServiceName='WinDefend'
Reject { & $exactReadService } 'Identity must be selected'
if ($script:queryCount -ne 1) { throw 'Invalid identity reached SCM query' }
Write-Output 'PASS production scope/collision/SCM exact-identity admission (injected boundaries, no SCM execution)'
