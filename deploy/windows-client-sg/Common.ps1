Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ServiceName = 'OrangeSpaceSinglePrototype.SG.v25'
$script:Root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OrangeSpace-SinglePrototype-SG-v25-20261104'
$script:State = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OrangeSpace-SinglePrototype-SG-v25-State'
$script:Image = '"' + (Join-Path $script:Root 'OrangeSpaceSinglePrototype.exe') + '"'
$script:Link = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'OrangeSpace.lnk'
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-Elevation([string]$Script) {
    if (Test-Admin) { return $false }
    # Paths cannot contain quotes in Win32. Do not change MachinePolicy/UserPolicy.
    $ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $ps -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','RemoteSigned','-File',('"'+$Script+'"'))
    if ($p.ExitCode -ne 0) { throw 'elevated-operation-failed' }
    return $true
}
if (-not ('OrangeInstallNative' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OrangeInstallNative {
 [StructLayout(LayoutKind.Sequential)] public struct Info {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
  public uint Volume,SizeHigh,SizeLow,NumberOfLinks,IndexHigh,IndexLow;
 }
 [StructLayout(LayoutKind.Sequential)] public struct Status {
  public uint Type,State,Accepted,Win32Exit,ServiceExit,Checkpoint,Hint,Pid,Flags;
 }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Config {
  public uint Type,Start,Error; public IntPtr Binary,Group; public uint Tag; public IntPtr Dependencies,Account,Display;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFileW(string p,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr OpenSCManagerW(string m,string db,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr OpenServiceW(IntPtr m,string name,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr CreateServiceW(IntPtr m,string name,string display,uint access,uint type,uint start,uint error,string image,string group,IntPtr tag,string deps,string account,string password);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool QueryServiceConfigW(IntPtr h,IntPtr buf,uint len,out uint needed);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool QueryServiceStatusEx(IntPtr h,int level,out Status s,uint len,out uint needed);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool SetServiceObjectSecurity(IntPtr h,uint info,byte[] sd);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool QueryServiceObjectSecurity(IntPtr h,uint info,byte[] sd,uint len,out uint needed);
 public static byte[] ReadServiceSecurity(IntPtr h) { uint n; QueryServiceObjectSecurity(h,4,null,0,out n); Need(n>0 && n<65536);byte[] b=new byte[n];Need(QueryServiceObjectSecurity(h,4,b,n,out n));return b; }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool StartServiceW(IntPtr h,uint argc,IntPtr args);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool DeleteService(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool ControlService(IntPtr h,uint control,IntPtr status);
 // PowerShell 5.1 coerces $null string arguments to empty strings. Keep
 // optional native LPCWSTR parameters as true C# null, not binder inputs.
 public static IntPtr OpenLocalManager(uint access) { return OpenSCManagerW(null,null,access); }
 public static IntPtr CreateLocalService(IntPtr m,string name,string display,string image) {
  return CreateServiceW(m,name,display,0xF01FF,16,2,1,image,null,IntPtr.Zero,null,"LocalSystem",null);
 }
 public static void Need(bool ok) { if(!ok) throw new InvalidOperationException("native-operation-failed:"+Marshal.GetLastWin32Error()); }
 public static Status ReadStatus(IntPtr h) { Status s; uint n; Need(QueryServiceStatusEx(h,0,out s,(uint)Marshal.SizeOf(typeof(Status)),out n));return s; }
 public static void VerifyConfig(IntPtr h,string image) {
  uint n; QueryServiceConfigW(h,IntPtr.Zero,0,out n); Need(n>0 && n<65536);
  IntPtr b=Marshal.AllocHGlobal((int)n);try { Need(QueryServiceConfigW(h,b,n,out n));Config c=(Config)Marshal.PtrToStructure(b,typeof(Config));
   Need(c.Type==16 && c.Start==2 && Marshal.PtrToStringUni(c.Binary)==image && Marshal.PtrToStringUni(c.Account)=="LocalSystem");
  } finally { Marshal.FreeHGlobal(b); }
 }
}
'@
}
function Assert-Ordinary([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse-refused' }
    return $item
}
function Assert-Ancestors([string]$Path, [bool]$Protected = $false) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        $null = Assert-Ordinary $cursor
        if ($Protected) {
            $acl = Get-Acl -LiteralPath $cursor
            $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'ancestor-owner-refused' }
            foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                $mask = 0x500D0156
                if ($cursor -eq [IO.Path]::GetPathRoot($cursor)) { $mask = 0x500D0040 }
                if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and ([int64]$rule.FileSystemRights -band $mask)) { throw 'ancestor-writable' }
            }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
}
function New-Policy([bool]$Directory, [bool]$Private = $false) {
    if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity; $inherit = 'OICI' }
    else { $acl = New-Object Security.AccessControl.FileSecurity; $inherit = '' }
    $sddl = 'O:BAG:BAD:P(A;'+$inherit+';FA;;;SY)(A;'+$inherit+';FA;;;BA)'
    if (!$Private) { $sddl += '(A;'+$inherit+';0x1200a9;;;BU)(A;'+$inherit+';0x1200a9;;;S-1-15-2-1)' }
    $acl.SetSecurityDescriptorSddlForm($sddl)
    $acl.SetAccessRuleProtection($true,$false)
    return $acl
}
function Assert-Policy([string]$Path, [bool]$Private = $false) {
    $null = Assert-Ordinary $Path
    $acl = Get-Acl -LiteralPath $Path
    if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'protected-dacl-required' }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $seen = @{}
    foreach ($r in $rules) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -ne 'Allow' -or $r.IsInherited) { throw 'unexpected-ace' }
        if ($sid -in @('S-1-5-18','S-1-5-32-544')) {
            if (([int64]$r.FileSystemRights -band 0x1f01ff) -ne 0x1f01ff) { throw 'privileged-rights-missing' }
        } elseif ($Private -or $sid -notin @('S-1-5-32-545','S-1-15-2-1') -or ([int64]$r.FileSystemRights -band 0x500D0156)) { throw 'foreign-access-refused' }
        $seen[$sid] = $true
    }
    if (!$seen.ContainsKey('S-1-5-18') -or !$seen.ContainsKey('S-1-5-32-544')) { throw 'privileged-ace-missing' }
    Assert-Ancestors ([IO.Path]::GetDirectoryName($Path)) $true
}
function Set-Policy([string]$Path, [bool]$Private = $false) {
    $item = Assert-Ordinary $Path
    Set-Acl -LiteralPath $Path -AclObject (New-Policy $item.PSIsContainer $Private)
    Assert-Policy $Path $Private
}
function New-ProtectedDirectory([string]$Path, [bool]$Private = $false) {
    if (Test-Path -LiteralPath $Path) { throw 'fresh-directory-required' }
    Assert-Ancestors ([IO.Path]::GetDirectoryName($Path)) $true
    $null = [IO.Directory]::CreateDirectory($Path, (New-Policy $true $Private))
    Assert-Policy $Path $Private
}
function Open-Pin([string]$Path) {
    $item = Assert-Ordinary $Path
    # FILE_SHARE_READ only: retain against write/rename until final copy verification.
    $flags = [uint32]0x00200000
    if ($item.PSIsContainer) { $flags = $flags -bor 0x02000000 }
    $h = [OrangeInstallNative]::CreateFileW($Path,2147483648,1,[IntPtr]::Zero,3,$flags,[IntPtr]::Zero)
    if ($h.IsInvalid) { $h.Dispose(); throw 'pin-open-failed' }
    $info = New-Object OrangeInstallNative+Info
    if (![OrangeInstallNative]::GetFileInformationByHandle($h,[ref]$info) -or ($info.Attributes -band 0x400) -or (!$item.PSIsContainer -and $info.NumberOfLinks -ne 1)) { $h.Dispose(); throw 'pin-identity-refused' }
    return $h
}
function Assert-Relative([string]$Rel) {
    if (!$Rel -or $Rel.Length -gt 220 -or $Rel -cnotmatch '\A[A-Za-z0-9_./-]+\z') { throw 'relative-path-refused' }
    foreach ($part in $Rel.Split('/')) {
        if (!$part -or $part -in @('.','..') -or $part.EndsWith('.') -or $part -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)') { throw 'relative-component-refused' }
    }
}
function Read-Inventory([string]$Directory) {
    $path = Join-Path $Directory 'runtime.inventory.tsv'
    $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::ASCII)
    if (!$raw.EndsWith("`n") -or $raw.Length -gt 1048576 -or $raw.Contains("`r")) { throw 'inventory-framing' }
    $rows = @{}
    foreach ($line in $raw.TrimEnd([char]10).Split([char]10)) {
        $v = $line.Split([char]9)
        if ($v.Count -ne 3 -or $v[0] -cnotmatch '\A[0-9a-f]{64}\z' -or $v[1] -cnotmatch '\A(?:0|[1-9][0-9]{0,14})\z') { throw 'inventory-row' }
        Assert-Relative $v[2]
        if ($v[2] -ieq 'runtime.inventory.tsv' -or $rows.ContainsKey($v[2])) { throw 'inventory-duplicate' }
        $rows[$v[2]] = @($v[0],[int64]$v[1])
    }
    if (!$rows.Count -or $rows.Count -gt 4096) { throw 'inventory-count' }
    return $rows
}
function Get-Tree([string]$Directory) {
    $null = Assert-Ordinary $Directory
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($Directory)
    $result = New-Object 'Collections.Generic.List[object]'
    while ($pending.Count) {
        $dir = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'tree-reparse-refused' }
            $rel = $item.FullName.Substring($Directory.Length+1).Replace('\','/')
            Assert-Relative $rel
            $result.Add($item)
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
        }
    }
    return $result.ToArray()
}
function Assert-Inventory([string]$Directory, $Rows, [bool]$Protected = $false) {
    $seen = @{}
    foreach ($item in @(Get-Tree $Directory)) {
        if ($Protected) { Assert-Policy $item.FullName }
        if ($item.PSIsContainer) { continue }
        $pin = Open-Pin $item.FullName
        try {
            $rel = $item.FullName.Substring($Directory.Length+1).Replace('\','/')
            if ($rel -ceq 'runtime.inventory.tsv') { continue }
            if (!$Rows.ContainsKey($rel) -or $seen.ContainsKey($rel)) { throw 'inventory-extra' }
            $seen[$rel] = $true
            if ($item.Length -ne $Rows[$rel][1] -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Rows[$rel][0]) { throw 'inventory-hash' }
        } finally { $pin.Dispose() }
    }
    if ($seen.Count -ne $Rows.Count) { throw 'inventory-missing' }
}
function Open-ServiceManager {
    $m = [OrangeInstallNative]::OpenLocalManager(3)
    [OrangeInstallNative]::Need($m -ne [IntPtr]::Zero)
    return $m
}
function Open-OwnedService($Manager, [uint32]$Access = 0xF01FF) {
    $s = [OrangeInstallNative]::OpenServiceW($Manager,$script:ServiceName,$Access)
    if ($s -eq [IntPtr]::Zero) {
        if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 1060) { return $s }
        throw 'service-open-failed'
    }
    try { [OrangeInstallNative]::VerifyConfig($s,$script:Image) }
    catch { $null = [OrangeInstallNative]::CloseServiceHandle($s); throw 'service-identity-refused' }
    return $s
}
function Set-ServicePolicy($Service) {
    # Users: QUERY_CONFIG (1) + QUERY_STATUS (4), no START/STOP/CHANGE_CONFIG.
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor('O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x5;;;BU)(A;;0x5;;;S-1-15-2-1)')
    $bytes = New-Object byte[] $sd.BinaryLength
    $sd.GetBinaryForm($bytes,0)
    [OrangeInstallNative]::Need([OrangeInstallNative]::SetServiceObjectSecurity($Service,4,$bytes))
    $actual = [OrangeInstallNative]::ReadServiceSecurity($Service)
    $readback = [Security.AccessControl.RawSecurityDescriptor]::new($actual,0)
    $wantedAcl = New-Object byte[] $sd.DiscretionaryAcl.BinaryLength
    $actualAcl = New-Object byte[] $readback.DiscretionaryAcl.BinaryLength
    $sd.DiscretionaryAcl.GetBinaryForm($wantedAcl,0)
    $readback.DiscretionaryAcl.GetBinaryForm($actualAcl,0)
    if ([Convert]::ToBase64String($actualAcl) -cne [Convert]::ToBase64String($wantedAcl)) { throw 'service-dacl-readback' }
}
function Wait-ServiceState($Service, [uint32]$Wanted) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $status = [OrangeInstallNative]::ReadStatus($Service)
        if ($status.State -eq $Wanted) { return $status }
        Start-Sleep -Milliseconds 200
    } while ($clock.Elapsed.TotalSeconds -lt 30)
    throw 'service-state-timeout'
}
function Assert-InstallManifest([string]$Directory) {
    $m = [IO.File]::ReadAllText((Join-Path $Directory 'install-manifest.json')) | ConvertFrom-Json
    if ($m.schema -ne 1 -or $m.kind -cne 'orangespace-single-sg-install' -or $m.root_leaf -cne 'OrangeSpace-SinglePrototype-SG-v25-20261104' -or $m.state_leaf -cne 'OrangeSpace-SinglePrototype-SG-v25-State' -or $m.service_name -cne $script:ServiceName -or $m.service_exe -cne 'OrangeSpaceSinglePrototype.exe' -or $m.gui_exe -cne 'OrangeSpace.exe') { throw 'install-manifest-identity' }
}
