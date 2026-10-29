param(
    [Parameter(Mandatory = $true)][string]$ServiceBinary,
    [Parameter(Mandatory = $true)][string]$ClientBinary,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ServiceSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ClientSha256
)
# Explicit, destructive only to this newly-created fixture. Requires administrator.
# Never logs on, reconnects/disconnects, changes a profile, or accepts a password.
$ErrorActionPreference = 'Stop'
$Name = 'OrangeSpaceFoundation'
$TaskName = 'OrangeSpace-Ipc-' + [guid]::NewGuid().ToString('N')
$Fixture = Join-Path $env:ProgramFiles $TaskName
$OwnedService = $false
$OwnedFixture = $false
$OwnedTask = $false
$Root = $null
$Failure = $null
$CleanupErrors = @()
function Assert-Hash([string]$Path, [string]$Expected) {
    $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($Hash -ne $Expected) { throw "Hash mismatch: $Path" }
    Write-Output "SHA256 $Path $Hash"
}
function Wait-ServiceState([string]$State) {
    $Until = [datetime]::UtcNow.AddSeconds(15)
    do {
        $S = Get-CimInstance Win32_Service -Filter "Name='$Name'"
        if ($S -and $S.State -eq $State) { return $S }
        Start-Sleep -Milliseconds 100
    } while ([datetime]::UtcNow -lt $Until)
    throw "Service did not become $State"
}
function Check-Running {
    $S = Wait-ServiceState 'Running'
    Write-Output "SCM observed StartName=$($S.StartName) Type=$($S.ServiceType) Path=$($S.PathName) PID=$($S.ProcessId)"
    if ($S.StartName -ne 'LocalSystem' -or $S.ServiceType -ne 'Own Process' -or
        $S.PathName -cne ('"' + $InstalledService + '"') -or $S.ProcessId -eq 0) {
        throw 'SCM configuration/PID mismatch'
    }
    $P = Get-CimInstance Win32_Process -Filter "ProcessId=$($S.ProcessId)"
    if (!$P -or $P.ExecutablePath -ine $InstalledService) { throw 'Service executable/PID mismatch' }
    Write-Output "SCM Running LocalSystem OwnProcess PID=$($S.ProcessId) Path=$($P.ExecutablePath)"
}
function Run-Client([string]$Label) {
    Remove-Item -LiteralPath (Join-Path $Results 'exit.txt') -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $Results 'client.txt') -Force -ErrorAction SilentlyContinue
    $Registered = $Root.GetTask($TaskName)
    $null = $Registered.Run($null)
    $Until = [datetime]::UtcNow.AddSeconds(60)
    while (!(Test-Path -LiteralPath (Join-Path $Results 'exit.txt'))) {
        if ((Test-Path -LiteralPath (Join-Path $Results 'old-ready.txt')) -and
            !(Test-Path -LiteralPath (Join-Path $Results 'stopped.txt'))) {
            Stop-Service -Name $Name
            $null = Wait-ServiceState 'Stopped'
            [IO.File]::WriteAllText((Join-Path $Results 'stopped.txt'), 'stopped')
            Write-Output 'PASS: service stopped with old client read pending'
        }
        if ((Test-Path -LiteralPath (Join-Path $Results 'old-failed.txt')) -and
            !(Test-Path -LiteralPath (Join-Path $Results 'restarted.txt'))) {
            Start-Service -Name $Name
            Check-Running
            Start-Sleep -Seconds 2
            [IO.File]::WriteAllText((Join-Path $Results 'restarted.txt'), 'restarted')
        }
        if ([datetime]::UtcNow -ge $Until) { throw "Client $Label timed out" }
        Start-Sleep -Milliseconds 50
    }
    $Code = [int](Get-Content -LiteralPath (Join-Path $Results 'exit.txt') -Raw)
    Write-Output "CLIENT $Label exit=$Code"
    Get-Content -LiteralPath (Join-Path $Results 'client.txt')
    if ($Code -ne 0) { throw "Installed handshake $Label failed: exit=$Code" }
}
try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (!(New-Object Security.Principal.WindowsPrincipal($Identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator required; no elevation or credentials are requested'
    }
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { throw 'Existing service: refusing any change' }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class IpcWts {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access,
        uint type, uint start, uint error, string path, string group, IntPtr tag,
        string dependencies, string account, string password);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
    public static void CreateFoundation(string path) {
        var scm=OpenSCManagerW(null,null,2);
        if(scm==IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try {
            var service=CreateServiceW(scm,"OrangeSpaceFoundation","OrangeSpaceFoundation",1,
                16,3,1,"\""+path+"\"",null,IntPtr.Zero,null,"LocalSystem",null);
            if(service==IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            CloseServiceHandle(service);
        } finally { CloseServiceHandle(scm); }
    }
    [StructLayout(LayoutKind.Sequential)] struct Info { public int Id; public IntPtr Name; public int State; }
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool WTSEnumerateSessionsW(IntPtr h, int r, int v, out IntPtr p, out int n);
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool WTSQuerySessionInformationW(IntPtr h, int id, int cls, out IntPtr p, out int n);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
    public static string Text(int id, int cls) {
        IntPtr p; int n;
        if (!WTSQuerySessionInformationW(IntPtr.Zero,id,cls,out p,out n)) throw new Exception("WTS query failed");
        try { return Marshal.PtrToStringUni(p); } finally { WTSFreeMemory(p); }
    }
    public static string[] DisconnectedUsers() {
        IntPtr p; int n; var users = new List<string>();
        if (!WTSEnumerateSessionsW(IntPtr.Zero,0,1,out p,out n)) throw new Exception("WTS enumerate failed");
        try {
            for (int i=0; i<n; ++i) {
                var s=(Info)Marshal.PtrToStructure(IntPtr.Add(p,i*Marshal.SizeOf(typeof(Info))),typeof(Info));
                if(s.Id==0 || s.State!=4) continue;
                var user=Text(s.Id,5); var domain=Text(s.Id,7);
                if(!String.IsNullOrEmpty(user)) users.Add(s.Id+"|"+domain+"\\"+user);
            }
        } finally { WTSFreeMemory(p); }
        return users.ToArray();
    }
}
'@
    $Candidates = @([IpcWts]::DisconnectedUsers())
    if ($Candidates.Count -ne 1) { throw 'Requires exactly one existing logged-on Disconnected nonzero session; no state changes allowed' }
    $Parts = $Candidates[0].Split('|')
    $SessionId = [int]$Parts[0]
    $User = $Parts[1]
    $Sid = (New-Object Security.Principal.NTAccount($User)).Translate([Security.Principal.SecurityIdentifier]).Value
    $BeforeSession = $Candidates[0]
    Write-Output "WTS before: Disconnected session=$SessionId user=$User"
    Assert-Hash $ServiceBinary $ServiceSha256
    Assert-Hash $ClientBinary $ClientSha256
    if (Test-Path -LiteralPath $Fixture) { throw 'Fixture must be fresh' }
    $Acl = New-Object Security.AccessControl.DirectorySecurity
    $Acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
    $null = [IO.Directory]::CreateDirectory($Fixture, $Acl)
    $OwnedFixture = $true
    $InstalledService = Join-Path $Fixture 'OrangeSpaceService.exe'
    $InstalledClient = Join-Path $Fixture 'service-client-tests.exe'
    Copy-Item -LiteralPath $ServiceBinary -Destination $InstalledService
    Copy-Item -LiteralPath $ClientBinary -Destination $InstalledClient
    Assert-Hash $InstalledService $ServiceSha256
    Assert-Hash $InstalledClient $ClientSha256
    $LockedAcl = Get-Acl -LiteralPath $Fixture
    if (!$LockedAcl.AreAccessRulesProtected) { throw 'Unprotected fixture ACL' }
    Write-Output "FIXTURE ACL $($LockedAcl.Sddl)"
    $Results = Join-Path $Fixture 'results'
    $ResultAcl = New-Object Security.AccessControl.DirectorySecurity
    $ResultAcl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$Sid)")
    $null = [IO.Directory]::CreateDirectory($Results, $ResultAcl)
    $Runner = Join-Path $Fixture 'run-client.ps1'
    @"
`$ErrorActionPreference = 'Stop'
try {
    if ([Diagnostics.Process]::GetCurrentProcess().SessionId -ne $SessionId) {
        throw 'Scheduled task did not enter the OS-enumerated Disconnected session'
    }
    `$ErrorActionPreference = 'Continue' # native stderr is evidence, not a PowerShell exception
    & '$InstalledClient' --installed-service --lifecycle-dir '$Results' 2>&1 | Out-File -LiteralPath '$Results\client.txt' -Encoding utf8
    `$Code = `$LASTEXITCODE
} catch {
    `$_ | Out-File -LiteralPath '$Results\client.txt' -Encoding utf8 -Append
    `$Code = 99
}
[IO.File]::WriteAllText('$Results\exit.txt', [string]`$Code)
exit `$Code
"@ | Set-Content -LiteralPath $Runner -Encoding UTF8
    $Scheduler = New-Object -ComObject Schedule.Service
    $Scheduler.Connect()
    $Root = $Scheduler.GetFolder('\')
    $Definition = $Scheduler.NewTask(0)
    $Definition.Principal.UserId = $User
    $Definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN: existing logon only
    $Definition.Principal.RunLevel = 0 # limited, never highest/elevated
    $Definition.Settings.ExecutionTimeLimit = 'PT90S'
    $Definition.Settings.DisallowStartIfOnBatteries = $false
    $Definition.Settings.StopIfGoingOnBatteries = $false
    $Action = $Definition.Actions.Create(0)
    $Action.Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $Action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Runner`""
    $null = $Root.RegisterTaskDefinition($TaskName, $Definition, 2, $User, $null, 3)
    $OwnedTask = $true
    $ReadTask = $Root.GetTask($TaskName).Definition
    if ($ReadTask.Principal.LogonType -ne 3 -or $ReadTask.Principal.RunLevel -ne 0) { throw 'Task principal mismatch' }
    # Fixed service name only; CreateService fails rather than overwriting if raced.
    [IpcWts]::CreateFoundation($InstalledService)
    $OwnedService = $true
    Start-Service -Name $Name
    Check-Running
    Start-Sleep -Seconds 2
    Run-Client 'initial-stop-restart'
    foreach ($Marker in @('old-ready.txt', 'stopped.txt', 'old-failed.txt', 'restarted.txt')) {
        if (!(Test-Path -LiteralPath (Join-Path $Results $Marker))) { throw "Missing lifecycle evidence $Marker" }
    }
    if ((@([IpcWts]::DisconnectedUsers()) -join ',') -cne $BeforeSession) { throw 'WTS state changed during test' }
    Write-Output "WTS after: unchanged Disconnected session=$SessionId"
} catch {
    $Failure = $_
    Write-Output "VALIDATION FAILED: $($_.Exception.Message)"
} finally {
    if ($OwnedTask) {
        try {
            $Root.GetTask($TaskName).Stop(0)
            $Root.DeleteTask($TaskName, 0)
            $Still = @($Root.GetTasks(0) | Where-Object { $_.Name -eq $TaskName })
            if ($Still.Count) { throw 'Task remains' }
            Write-Output 'CLEANUP: task absent'
        } catch { $CleanupErrors += $_ }
    }
    if ($OwnedService) {
        try {
            $OwnedConfig = Get-CimInstance Win32_Service -Filter "Name='$Name'"
            if (!$OwnedConfig -or $OwnedConfig.PathName -cne ('"' + $InstalledService + '"') -or
                $OwnedConfig.StartName -ne 'LocalSystem') { throw 'Cleanup refused: owned service config no longer matches' }
            $S = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($S -and $S.Status -ne 'Stopped') { Stop-Service -Name $Name }
            $null = Wait-ServiceState 'Stopped'
            & sc.exe delete $Name
            if ($LASTEXITCODE -ne 0) { throw 'DeleteService failed' }
            $Until = [datetime]::UtcNow.AddSeconds(10)
            while (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
                if ([datetime]::UtcNow -gt $Until) { throw 'Service remains' }
                Start-Sleep -Milliseconds 100
            }
            Write-Output 'CLEANUP: service absent'
        } catch { $CleanupErrors += $_ }
    }
    if ($OwnedFixture) {
        try {
            $Processes = @(Get-CimInstance Win32_Process | Where-Object {
                ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($Fixture + '\', [StringComparison]::OrdinalIgnoreCase)) -or
                ($Runner -and $_.CommandLine -and $_.CommandLine.IndexOf($Runner, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            })
            foreach ($P in $Processes) { Stop-Process -Id $P.ProcessId -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 300
            $Remaining = @(Get-CimInstance Win32_Process | Where-Object {
                ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($Fixture + '\', [StringComparison]::OrdinalIgnoreCase)) -or
                ($Runner -and $_.CommandLine -and $_.CommandLine.IndexOf($Runner, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            })
            if ($Remaining.Count) { throw 'Fixture processes remain' }
            Write-Output 'CLEANUP: fixture binary processes absent'
            Remove-Item -LiteralPath $Fixture -Recurse -Force
            if (Test-Path -LiteralPath $Fixture) { throw 'Fixture directory remains' }
            Write-Output "CLEANUP: fixture absent $Fixture"
        } catch { $CleanupErrors += $_ }
    }
    if ($BeforeSession) {
        try {
            if ((@([IpcWts]::DisconnectedUsers()) -join ',') -cne $BeforeSession) { throw 'WTS session changed' }
            Write-Output "CLEANUP: WTS still Disconnected session=$SessionId"
        } catch { $CleanupErrors += $_ }
    }
}
if ($CleanupErrors.Count) { $CleanupErrors | ForEach-Object { Write-Output "CLEANUP ERROR: $_" }; exit 2 }
if ($Failure) { exit 1 }
Write-Output 'PASS: installed service IPC initial/restart and cleanup'
