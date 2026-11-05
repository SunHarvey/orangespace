# Windows PowerShell 5.1; script intentionally ASCII.
. (Join-Path $PSScriptRoot 'Common.ps1')
$stage = 'preflight'
$pins = New-Object 'Collections.Generic.List[IDisposable]'
$manager = [IntPtr]::Zero
$service = [IntPtr]::Zero
$stateStaging = $null
try {
    if (Invoke-Elevation $PSCommandPath) {
        # This branch is the original unelevated caller, never the UAC child.
        & (Join-Path $PSScriptRoot 'Start.ps1')
        exit $LASTEXITCODE
    }
    if (Test-Path -LiteralPath $script:Root) { throw 'existing-installation-refused' }
    Assert-Ancestors ([Environment]::GetFolderPath('ProgramFiles')) $true
    $manager = Open-ServiceManager
    $service = Open-OwnedService $manager
    if ($service -ne [IntPtr]::Zero) { throw 'existing-service-refused' }
    $source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Runtime'))
    Assert-Ancestors $source
    # Retain root and every descendant against writer/rename, including manifest.
    $cursor = $source
    while ($cursor) {
        $pins.Add((Open-Pin $cursor))
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    $tree = @(Get-Tree $source)
    foreach ($entry in $tree) { $pins.Add((Open-Pin $entry.FullName)) }
    $rows = Read-Inventory $source
    Assert-Inventory $source $rows
    Assert-InstallManifest $source
    foreach ($required in @('platform.json','nodes.json','sing-box.exe','OrangeSpace.exe','OrangeSpaceSinglePrototype.exe','client.exe','client.dll','libcef.dll')) {
        if (!$rows.ContainsKey($required)) { throw 'required-payload-missing' }
    }
    $stage = 'protected-copy'
    $staging = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('OrangeSpace-SG-stage-' + [Guid]::NewGuid().ToString('N'))
    New-ProtectedDirectory $staging
    foreach ($entry in @($tree | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length })) {
        New-ProtectedDirectory (Join-Path $staging $entry.FullName.Substring($source.Length+1))
    }
    foreach ($entry in @($tree | Where-Object { !$_.PSIsContainer })) {
        $dest = Join-Path $staging $entry.FullName.Substring($source.Length+1)
        $inputFile = [IO.File]::Open($entry.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $outputFile = [IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $inputFile.CopyTo($outputFile); $outputFile.Flush($true) }
            finally { $outputFile.Dispose() }
        } finally { $inputFile.Dispose() }
        Set-Policy $dest
    }
    Assert-Inventory $source $rows
    Assert-Inventory $staging $rows $true
    Assert-InstallManifest $staging
    # Existing ledger is never overwritten, repaired or reset. Native Service
    # performs its strict full ownership/generation parser before accepting work.
    $stage = 'private-state'
    $manifest = [IO.File]::ReadAllText((Join-Path $staging 'install-manifest.json')) | ConvertFrom-Json
    $hasPreservedState = 'initial_state' -cin @($manifest.PSObject.Properties.Name)
    if (!$hasPreservedState) { throw 'fresh-state-not-authorized' }
    $bindingText = $script:ServiceName
    foreach ($name in @('namespace.anchor','service-state.json')) {
        $meta = $manifest.initial_state.$name
        if ($meta.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $meta.size -le 0 -or $meta.size -gt 1048576) { throw 'preserved-state-metadata' }
        $bindingText += "`n" + $name + ':' + $meta.sha256 + ':' + $meta.size
    }
    $bindingName = 'installer-state-binding.json'
    if (Test-Path -LiteralPath $script:State) {
        Assert-Policy $script:State $true
        $stateItems = @(Get-ChildItem -LiteralPath $script:State -Force)
        if ($stateItems.Count -gt 4096) { throw 'existing-state-scope-refused' }
        $bindingPath = Join-Path $script:State $bindingName
        $bound = $false
        foreach ($item in $stateItems) {
            if ($item.Name -cnotin @('namespace.anchor','service-state.json',$bindingName) -and $item.Name -cnotmatch '\AOS\.SG\.[0-9a-f]{48}\.profile\z') { throw 'existing-state-scope-refused' }
            Assert-Policy $item.FullName $true
            $pin = Open-Pin $item.FullName
            try {
                if ($item.PSIsContainer -or $item.Length -gt 1048576) { throw 'existing-state-leaf-refused' }
                if ($item.Name -ceq $bindingName) {
                    if ([IO.File]::ReadAllText($bindingPath) -cne $bindingText) { throw 'existing-state-binding-refused' }
                    $bound = $true
                }
            } finally { $pin.Dispose() }
        }
        foreach ($name in @('namespace.anchor','service-state.json')) {
            $leaf = Join-Path $script:State $name
            Assert-Policy $leaf $true
            $pin = Open-Pin $leaf
            try {
                if ((Get-Item -LiteralPath $leaf).PSIsContainer) { throw 'state-file-required' }
                $size = (Get-Item -LiteralPath $leaf).Length
                if ($size -le 0 -or $size -gt 1048576) { throw 'existing-state-size-refused' }
                # A persisted installer receipt permits ledger evolution, never anchor replacement.
                # Profile markers are preserved data, not trusted configuration. Service parses ownership.
                if (!$bound -or $name -ceq 'namespace.anchor') {
                    $meta = $manifest.initial_state.$name
                    if ($size -ne $meta.size -or (Get-FileHash -LiteralPath $leaf).Hash.ToLowerInvariant() -cne $meta.sha256) { throw 'existing-state-binding-refused' }
                }
            } finally { $pin.Dispose() }
        }
        $statePath = Join-Path $script:State 'service-state.json'
        $stateSize = (Get-Item -LiteralPath $statePath).Length
        if ($stateSize -le 0 -or $stateSize -gt 1048576) { throw 'existing-state-size-refused' }
        $existing = [IO.File]::ReadAllText($statePath) | ConvertFrom-Json
        if ($existing.schema -notin @(1,2) -or $null -eq $existing.sandboxes) { throw 'existing-state-format-refused' }
    } else {

        $stateStaging = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('OrangeSpace-SG-state-stage-' + [Guid]::NewGuid().ToString('N'))
        New-ProtectedDirectory $stateStaging $true
        if ($hasPreservedState) {
            $stateSource = Join-Path $PSScriptRoot 'State'
            $pins.Add((Open-Pin $stateSource))
            $pair = @(Get-ChildItem -LiteralPath $stateSource -Force)
            if ($pair.Count -ne 2) { throw 'preserved-state-scope' }
            if (@($manifest.initial_state.PSObject.Properties.Name).Count -ne 2) { throw 'preserved-state-manifest' }
            foreach ($name in @('namespace.anchor','service-state.json')) {
                $sourceLeaf = Join-Path $stateSource $name
                $pins.Add((Open-Pin $sourceLeaf))
                $meta = $manifest.initial_state.$name
                if ($meta.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $meta.size -le 0 -or $meta.size -gt 1048576) { throw 'preserved-state-metadata' }
                $dest = Join-Path $stateStaging $name
                $inputFile = [IO.File]::Open($sourceLeaf,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try {
                    $outputFile = [IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                    try { $inputFile.CopyTo($outputFile); $outputFile.Flush($true) }
                    finally { $outputFile.Dispose() }
                } finally { $inputFile.Dispose() }
                Set-Policy $dest $true
                if ((Get-Item -LiteralPath $dest).Length -ne $meta.size -or (Get-FileHash -LiteralPath $dest).Hash.ToLowerInvariant() -cne $meta.sha256) { throw 'preserved-state-hash' }
            }
            $restored = [IO.File]::ReadAllText((Join-Path $stateStaging 'service-state.json')) | ConvertFrom-Json
            if ($restored.schema -notin @(1,2) -or $null -eq $restored.sandboxes) { throw 'preserved-state-format' }
        } else {
            # A genuinely fresh instance only. Existing private State above can
            # never reach this initializer; supplied prior State is copied intact.
            foreach ($name in @('namespace.anchor','service-state.json')) {
                $leaf = Join-Path $stateStaging $name
                if ($name -eq 'namespace.anchor') { $text = "OrangeSpace.SinglePrototype.SG.v25`n" }
                else { $text = '{"schema":1,"sandboxes":[]}' + "`n" }
                $f = [IO.File]::Open($leaf,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try { $bytes = [Text.Encoding]::ASCII.GetBytes($text); $f.Write($bytes,0,$bytes.Length); $f.Flush($true) }
                finally { $f.Dispose() }
                Set-Policy $leaf $true
            }
        }
        Assert-Policy $stateStaging $true
        foreach ($name in @('namespace.anchor','service-state.json')) { Assert-Policy (Join-Path $stateStaging $name) $true }
    }
    # All source reads and both protected snapshots are complete. Retaining
    # Program Files without DELETE sharing would block our own sibling rename.
    # Release inputs only after final snapshot verification; never read them again.
    Assert-Inventory $staging $rows $true
    Assert-InstallManifest $staging
    foreach ($pin in $pins) { $pin.Dispose() }
    $pins.Clear()
    if ($stateStaging) {
        [IO.Directory]::Move($stateStaging,$script:State)
        Assert-Policy $script:State $true
        foreach ($name in @('namespace.anchor','service-state.json')) { Assert-Policy (Join-Path $script:State $name) $true }
    }
    # Create once only after exact original-pair validation; never reset or rewrite State.
    $bindingPath = Join-Path $script:State $bindingName
    if (!(Test-Path -LiteralPath $bindingPath)) {
        $f = [IO.File]::Open($bindingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $bytes = [Text.Encoding]::ASCII.GetBytes($bindingText); $f.Write($bytes,0,$bytes.Length); $f.Flush($true) }
        finally { $f.Dispose() }
        Set-Policy $bindingPath $true
    }
    # A same-name preexisting desktop shortcut is never silently replaced.
    if (Test-Path -LiteralPath $script:Link) { throw 'desktop-shortcut-conflict' }
    $stage = 'promote'
    [IO.Directory]::Move($staging,$script:Root)
    Assert-Policy $script:Root
    Assert-Inventory $script:Root $rows $true
    # Explicit fixed quoted binary, OWN_PROCESS=16, AUTO_START=2, NORMAL=1,
    # LocalSystem account, no password, no credentials in arguments/environment.
    $stage = 'service-create'
    $service = [OrangeInstallNative]::CreateLocalService($manager,$script:ServiceName,'OrangeSpace SG',$script:Image)
    [OrangeInstallNative]::Need($service -ne [IntPtr]::Zero)
    [OrangeInstallNative]::VerifyConfig($service,$script:Image)
    Set-ServicePolicy $service
    [OrangeInstallNative]::Need([OrangeInstallNative]::StartServiceW($service,0,[IntPtr]::Zero))
    $null = Wait-ServiceState $service 4
    $stage = 'desktop-shortcut'
    $shell = New-Object -ComObject WScript.Shell
    $desktopLink = $shell.CreateShortcut($script:Link)
    $desktopLink.TargetPath = Join-Path $script:Root 'OrangeSpace.exe'
    $desktopLink.WorkingDirectory = $script:Root
    $desktopLink.IconLocation = (Join-Path $script:Root 'OrangeSpace.exe') + ',0'
    $desktopLink.Description = 'OrangeSpace SG'
    $desktopLink.Save()
    $readback = $shell.CreateShortcut($script:Link)
    if ($readback.TargetPath -cne (Join-Path $script:Root 'OrangeSpace.exe') -or $readback.Arguments) { throw 'shortcut-readback-failed' }
    # Shortcut is not a trust-input ancestor; Public Desktop may legitimately
    # permit user-created siblings. Protect this owned leaf without changing it.
    Set-Acl -LiteralPath $script:Link -AclObject (New-Policy $false)
    $linkAcl = Get-Acl -LiteralPath $script:Link
    if (!$linkAcl.AreAccessRulesProtected) { throw 'shortcut-acl-readback-failed' }
    Write-Host 'install-complete: use the OrangeSpace desktop shortcut as an ordinary user.'
    exit 0
} catch {
    # Fixed labels only, never exception/configuration/credential bodies.
    Write-Host ('install-failed:' + $stage + '; owned files retained for inspection; no blind rollback.')
    exit 1
} finally {
    foreach ($pin in $pins) { $pin.Dispose() }
    if ($service -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($service) }
    if ($manager -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($manager) }
}
