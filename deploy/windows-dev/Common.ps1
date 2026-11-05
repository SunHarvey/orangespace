Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ServiceName = $null
$script:Names = @('OrangeSpace.exe','OrangeSpaceLogin.exe','OrangeSpaceService.exe','orangespace-broker.exe','sing-box.exe')
$script:HelperHash = '8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9'
function Assert-Admin {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows required' }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (!(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
}
function Assert-Ordinary([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point refused' }
    return $item
}
function Assert-Protected([string]$Path, [bool]$Private = $false) {
    $item = Assert-Ordinary $Path
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if ($owner -notin $trusted) { throw 'Owner must be SYSTEM or Administrators' }
    if (!$acl.AreAccessRulesProtected) { throw 'Explicit protected DACL required' }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (!$rules.Count) { throw 'Empty DACL refused' }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow') { throw 'Unexpected ACL rule' }
        if ($rule.IdentityReference.Value -notin $trusted) {
            if ($Private) { throw 'Private file accessible to other principal' }
            $mask = [int64]$rule.FileSystemRights
            # WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete, WRITE_DAC, WRITE_OWNER.
            if ($mask -band 0x500D0156) { throw 'Unprivileged write ACL refused' }
        }
    }
    if ($item.PSIsContainer) { $cursor = $item.Parent } else { $cursor = $item.Directory }
    while ($null -ne $cursor) {
        $null = Assert-Ordinary $cursor.FullName
        # Ancestors may inherit; only privileged owners and no effective foreign
        # write/delete-child permissions. Drive root permits creating siblings,
        # but must not permit deleting/changing this protected descendant.
        $ancestorAcl = Get-Acl -LiteralPath $cursor.FullName
        $ancestorOwner = $ancestorAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $ancestorTrusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if ($ancestorOwner -notin $ancestorTrusted) { throw 'Untrusted ancestor owner' }
        foreach ($r in @($ancestorAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
            if (($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin $ancestorTrusted) {
                $bad = 0x500D0156
                if ($null -eq $cursor.Parent) { $bad = 0x500D0040 }
                if ([int64]$r.FileSystemRights -band $bad) { throw 'Writable ancestor refused' }
            }
        }
        $cursor = $cursor.Parent
    }
}
function Set-Protected([string]$Path, [bool]$Directory = $false, [bool]$Private = $false) {
    if ($Directory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        $sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
        if ($Private) { $sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' }
    }
    $acl.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-Protected $Path $Private
}
function Select-InstallIdentity($Manifest, [string]$Root) {
    $id = ''
    $properties = @($Manifest.PSObject.Properties.Name)
    $identityFields = @('development_install_id','service_name','pipe_prefix')
    $present = @($identityFields | Where-Object { $_ -cin $properties })
    if ($present.Count -ne 0 -and $present.Count -ne 3) { throw 'Incomplete install identity' }
    if ($present.Count -eq 3) {
        if ($Manifest.development_install_id -isnot [string]) { throw 'Invalid install identity type' }
        $id = $Manifest.development_install_id
        if ($id -cnotmatch '\A[a-z0-9-]{1,24}\z') { throw 'Invalid development install identity' }
    }
    $name = 'OrangeSpaceFoundation'
    $pipe = '\\.\pipe\OrangeSpace.Foundation'
    if ($id) { $name += '.Dev.' + $id; $pipe += '.Dev.' + $id }
    $pipe += '.v1.session.'
    if ($present.Count -eq 3 -and ($Manifest.service_name -cne $name -or $Manifest.pipe_prefix -cne $pipe)) { throw 'Manifest namespace mismatch' }
    $record = 'OrangeSpace.InstallIdentity.v1|' + $id + '|' + $name + [char]0 + $pipe
    foreach ($binary in @('OrangeSpace.exe','OrangeSpaceLogin.exe','OrangeSpaceService.exe')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Root $binary))
        $text = [Text.Encoding]::Unicode.GetString($bytes)
        $records = [regex]::Matches($text, 'OrangeSpace\.InstallIdentity\.v1\|[^\x00]{1,128}\x00[^\x00]{1,128}')
        if ($records.Count -eq 0) {
            # Legacy default build has no provenance record; require its exact fixed namespace.
            if ($id -or !$text.Contains($name) -or !$text.Contains($pipe)) { throw 'Binary namespace provenance mismatch' }
        } else {
            foreach ($found in $records) {
                if ($found.Value -cne $record) { throw 'Binary namespace provenance mismatch' }
            }
        }
    }
    $script:ServiceName = $name
}
function Get-Manifest([string]$Root, [bool]$Installed = $false, $Snapshot = $null) {
    $script:ServiceName = $null
    # Every source leaf and all ancestors must be protected before content is read.
    Assert-Protected $Root
    Assert-Protected (Join-Path $Root 'manifest.json')
    foreach ($name in $script:Names) { Assert-Protected (Join-Path $Root $name) }
    $null = Assert-Ordinary $Root
    $allowed = @($script:Names) + @('manifest.json')
    if ($Installed) { $allowed += @('platform.json','nodes.json','service-state.json','.orangespace-dev.json','service-state.next') }
    $entries = @(Get-ChildItem -LiteralPath $Root -Force)
    foreach ($entry in $entries) {
        if ($entry.Name -cnotin $allowed -or $entry.PSIsContainer) { throw 'Unexpected package/config/data entry' }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point refused' }
    }
    $manifestPath = Join-Path $Root 'manifest.json'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    if ($null -ne $Snapshot) {
        if ($manifestHash -cne $Snapshot.manifestHash) { throw 'Frozen manifest snapshot mismatch' }
        # Never authorize destination payload from destination self-description.
        $m = $Snapshot
    } else {
        $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne $manifestHash) { throw 'Source manifest changed during snapshot' }
        $m | Add-Member -NotePropertyName manifestHash -NotePropertyValue $manifestHash
    }
    if ($m.schema -ne 1 -or $m.kind -cne 'orangespace-windows-dev' -or @($m.files).Count -ne 5) { throw 'Manifest schema/count refused' }
    $seen = @{}
    foreach ($row in $m.files) {
        if ($row.name -cnotin $script:Names -or $seen.ContainsKey($row.name)) { throw 'Manifest scope/duplicate refused' }
        $seen[$row.name] = $true
        if ($row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $row.size -le 0) { throw 'Manifest metadata refused' }
        $file = Assert-Ordinary (Join-Path $Root $row.name)
        if ($file.PSIsContainer -or $file.Length -ne $row.size -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.sha256) { throw 'Exact binary size/hash refused' }
        if ($row.name -ceq 'sing-box.exe' -and $row.sha256 -cne $script:HelperHash) { throw 'Pinned helper refused' }
        if ($Installed) { Assert-Protected $file.FullName }
    }
    Select-InstallIdentity $m $Root
    return $m
}
function Get-Target([string]$Leaf) {
    if ($Leaf -cnotmatch '^OrangeSpace-Dev-[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw 'Invalid fixed development leaf' }
    $pf = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (!$pf -or $pf -notmatch '^[A-Za-z]:\\') { throw 'Local Program Files required' }
    $null = Assert-Ordinary $pf
    return Join-Path $pf $Leaf
}
function Read-Service {
    if (!$script:ServiceName -or $script:ServiceName -cnotmatch '\AOrangeSpaceFoundation(?:\.Dev\.[a-z0-9-]{1,24})?\z') { throw 'Identity must be selected from a protected manifest' }
    $rows = @(Get-CimInstance Win32_Service -Filter "Name='$script:ServiceName'")
    if ($rows.Count -gt 1) { throw 'Ambiguous service' }
    if ($rows.Count -eq 0) { return $null }
    return $rows[0]
}
function Assert-Installed([string]$Root) {
    Assert-Protected $Root
    Assert-Protected (Join-Path $Root '.orangespace-dev.json')
    Assert-Protected (Join-Path $Root 'manifest.json')
    $m = Get-Manifest $Root $true
    $marker = Get-Content -LiteralPath (Join-Path $Root '.orangespace-dev.json') -Raw | ConvertFrom-Json
    $image = '"' + (Join-Path $Root 'OrangeSpaceService.exe') + '"'
    if ($marker.kind -cne 'orangespace-windows-dev-install-v1' -or $marker.root -cne $Root -or $marker.service -cne $script:ServiceName -or $marker.image -cne $image) { throw 'Installation marker mismatch' }
    if ((Get-FileHash -LiteralPath (Join-Path $Root 'manifest.json')).Hash -cne $marker.manifestHash) { throw 'Manifest drift' }
    foreach ($name in @('platform.json','nodes.json')) {
        Assert-Protected (Join-Path $Root $name)
        if ((Get-FileHash -LiteralPath (Join-Path $Root $name)).Hash -cne $marker.configHashes.$name) { throw 'Protected configuration drift' }
    }
    Assert-Protected (Join-Path $Root 'service-state.json') $true
    $s = Read-Service
    if ($null -eq $s) { throw 'Required project Service is absent' }
    if ($s.Name -cne $script:ServiceName -or $s.PathName -cne $image -or $s.StartName -cne 'LocalSystem' -or $s.ServiceType -cne 'Own Process' -or $s.StartMode -cne 'Manual') { throw 'SCM identity/configuration mismatch' }
    return $s
}
function Wait-State([string]$Root, [string]$Expected) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $s = Assert-Installed $Root
        if ($s.State -ceq $Expected) { return $s }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'SCM state timeout; no kill or rollback attempted'
}
