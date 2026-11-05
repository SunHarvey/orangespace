param(
    [Parameter(Mandatory=$true)][ValidateSet('install','start','stop','status','uninstall')][string]$Action,
    [Parameter(Mandatory=$true)][string]$Leaf,
    [string]$Package,
    [string]$ProtectedConfig
)
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Admin
$root = Get-Target $Leaf
if ($Action -eq 'install') {
    if (Test-Path -LiteralPath $root) { throw 'Existing target refused; no overwrite or adoption' }
    if (!$Package -or !$ProtectedConfig) { throw 'Package and external protected config required' }
    $manifest = Get-Manifest $Package
    if ($null -ne (Read-Service)) { throw 'Existing project Service refused' }
    Assert-Protected $ProtectedConfig $true
    $configNames = @('platform.json','nodes.json','service-state.json')
    if (@(Get-ChildItem -LiteralPath $ProtectedConfig -Force).Count -ne 3) { throw 'External config must contain exactly platform/nodes/service-state JSON' }
    foreach ($name in $configNames) {
        $path = Join-Path $ProtectedConfig $name
        Assert-Protected $path ($name -eq 'service-state.json')
        # Parse without printing endpoints, identities, tokens or config exceptions.
        try { $null = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { throw 'Invalid protected configuration JSON' }
    }
    # Fresh, explicit target only. Failure leaves it for inspection; never broad cleanup.
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    Set-Protected $root $true
    foreach ($name in @($script:Names) + @('manifest.json')) {
        Copy-Item -LiteralPath (Join-Path $Package $name) -Destination (Join-Path $root $name)
        Set-Protected (Join-Path $root $name)
    }
    $hashes = @{}
    foreach ($name in $configNames) {
        $dest = Join-Path $root $name
        Copy-Item -LiteralPath (Join-Path $ProtectedConfig $name) -Destination $dest
        Set-Protected $dest $false ($name -eq 'service-state.json')
        $hashes[$name] = (Get-FileHash -LiteralPath $dest).Hash
        if ($hashes[$name] -cne (Get-FileHash -LiteralPath (Join-Path $ProtectedConfig $name)).Hash) { throw 'Config changed during copy' }
    }
    $null = Get-Manifest $root $true $manifest
    $image = '"' + (Join-Path $root 'OrangeSpaceService.exe') + '"'
    $marker = @{kind='orangespace-windows-dev-install-v1'; root=$root; service=$script:ServiceName; image=$image; manifestHash=(Get-FileHash -LiteralPath (Join-Path $root 'manifest.json')).Hash; configHashes=$hashes}
    $marker | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root '.orangespace-dev.json') -Encoding UTF8
    Set-Protected (Join-Path $root '.orangespace-dev.json')
    if ($null -ne (Read-Service)) { throw 'Service appeared; refusing registration' }
    $r = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name=$script:ServiceName; DisplayName='OrangeSpace Foundation'; PathName=$image;
        ServiceType=[byte]16; ErrorControl=[byte]1; StartMode='Manual';
        DesktopInteract=$false; StartName='LocalSystem'; StartPassword=$null
    }
    if ($r.ReturnValue -ne 0) { throw 'SCM Create failed; retained owned target' }
    $s = Wait-State $root 'Stopped'
} else {
    $s = Assert-Installed $root
    switch ($Action) {
        'start' {
            if ($s.State -cne 'Stopped') { throw 'Start requires Stopped state' }
            $r = Invoke-CimMethod -InputObject $s -MethodName StartService
            if ($r.ReturnValue -ne 0) { throw 'SCM start failed' }
            $s = Wait-State $root 'Running'
        }
        'stop' {
            if ($s.State -cne 'Running') { throw 'Stop requires Running state' }
            $r = Invoke-CimMethod -InputObject $s -MethodName StopService
            if ($r.ReturnValue -ne 0) { throw 'SCM stop failed' }
            $s = Wait-State $root 'Stopped'
        }
        'uninstall' {
            if ($s.State -cne 'Stopped') { throw 'Explicit verified stop required before uninstall' }
            $r = Invoke-CimMethod -InputObject $s -MethodName Delete
            if ($r.ReturnValue -ne 0) { throw 'SCM delete failed' }
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                if ($null -eq (Read-Service)) { Write-Output 'Uninstalled: exact Service absent; protected files retained.'; return }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $deadline)
            throw 'SCM deletion still pending; retained files'
        }
    }
}
[pscustomobject]@{Name=$s.Name; State=$s.State; ProcessId=$s.ProcessId; StartName=$s.StartName; PathName=$s.PathName; Win32ExitCode=$s.ExitCode}
