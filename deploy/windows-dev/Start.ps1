param([Parameter(Mandatory=$true)][string]$Leaf)
. (Join-Path $PSScriptRoot 'Common.ps1')
if ($env:OS -ne 'Windows_NT') { throw 'Windows required' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Launch Manager from a limited interactive console, not elevated' }
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Interactive session required' }
$root = Get-Target $Leaf
Assert-Protected $root
$null = Get-Manifest $root $true
foreach ($name in @('manifest.json','platform.json','nodes.json','.orangespace-dev.json')) { Assert-Protected (Join-Path $root $name) }
$m = Get-Content -LiteralPath (Join-Path $root '.orangespace-dev.json') -Raw | ConvertFrom-Json
$image = '"' + (Join-Path $root 'OrangeSpaceService.exe') + '"'
if ($m.kind -cne 'orangespace-windows-dev-install-v1' -or $m.root -cne $root -or $m.service -cne $script:ServiceName -or $m.image -cne $image) { throw 'Marker mismatch' }
if ((Get-FileHash -LiteralPath (Join-Path $root 'manifest.json')).Hash -cne $m.manifestHash) { throw 'Manifest drift' }
foreach ($name in @('platform.json','nodes.json')) {
    if ((Get-FileHash -LiteralPath (Join-Path $root $name)).Hash -cne $m.configHashes.$name) { throw 'Protected configuration drift' }
}
$s = Read-Service
if ($null -eq $s -or $s.State -cne 'Running' -or $s.PathName -cne $image -or $s.StartName -cne 'LocalSystem' -or $s.ServiceType -cne 'Own Process' -or $s.StartMode -cne 'Manual') { throw 'Required exact project Service is not Running' }
$p = Start-Process -FilePath (Join-Path $root 'OrangeSpace.exe') -WorkingDirectory $root -PassThru
Start-Sleep -Milliseconds 300
$p.Refresh()
if ($p.HasExited) { throw 'Manager exited during startup; UI acceptance not established' }
[pscustomobject]@{ManagerPid=$p.Id; State='ProcessCreatedOnly'; PlatformConfig=(Join-Path $root 'platform.json'); BrowserAllowed=$false}
