# No credentials in this file or command line. Parent supplies one framed JSON
# bootstrap on SSH stdin; normal Selftest does not contact any API or create SCM.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$SourceDirectory,
 [Parameter(Mandatory=$true)][string]$ClientSha256,
 [Parameter(Mandatory=$true)][string]$ControllerSha256,
 [Parameter(Mandatory=$true)][string]$CatalogSha256,
 [ValidateSet('Selftest','Accept')][string]$Mode='Selftest',
 [string]$ServiceSha256='', [string]$HelperSha256='',
 [ValidateSet('None','BadBootstrap','TruncatedBootstrap')][string]$Fault='None'
)
# This is a source safety quarantine, not an execution-policy workaround.
# RemoteSigned authorization remains valid; it does not approve this fixture.
throw 'phase1 fixture quarantined: S1-S5/L1-L3 require independent review; Selftest and Accept disabled'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($Mode -eq 'Accept' -and $Fault -ne 'None'){throw 'fault probes are bootstrap-only selftests'}
function Read-Exact([System.IO.Stream]$Stream,[int]$Count,[int]$TimeoutMs) {
 $b=New-Object byte[] $Count
 $offset=0
 $deadline=[DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
 try {
  while($offset -lt $Count){
   $pending=$Stream.BeginRead($b,$offset,$Count-$offset,$null,$null)
   $left=[Math]::Max(0,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds)
   if(-not $pending.AsyncWaitHandle.WaitOne($left)){ $Stream.Dispose();throw 'bounded framed read timeout' }
   try { $n=$Stream.EndRead($pending) } finally { $pending.AsyncWaitHandle.Dispose() }
   if($n -le 0){throw 'framed stream closed'}
   $offset+=$n
  }
  return ,$b
 }catch{[Array]::Clear($b,0,$b.Length);throw}
}
function Read-Frame([System.IO.Stream]$Stream,[int]$TimeoutMs) {
 $header=Read-Exact $Stream 4 $TimeoutMs
 $count=[BitConverter]::ToUInt32($header,0)
 if($count -lt 1 -or $count -gt 32768){throw 'invalid frame length'}
 return ,(Read-Exact $Stream ([int]$count) $TimeoutMs)
}
function Send-Frame([System.IO.Stream]$Stream,[byte[]]$Payload) {
 if($Payload.Length -lt 1 -or $Payload.Length -gt 32768){throw 'invalid bootstrap length'}
 $header=[BitConverter]::GetBytes([uint32]$Payload.Length)
 $Stream.Write($header,0,4);$Stream.Write($Payload,0,$Payload.Length);$Stream.Flush()
}
function Service-Baseline {
 @(Get-CimInstance Win32_Service | Sort-Object Name | Select-Object Name,State,StartMode,ProcessId,PathName,StartName,ServiceType)
}
function Verify-Hash([string]$Path,[string]$Expected) {
 if($Expected -cnotmatch '^[a-f0-9]{64}$'){throw 'invalid expected SHA256'}
 if((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -cne $Expected){throw 'artifact SHA256 mismatch'}
}
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Phase1PipeNative {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
}
'@
$root='C:\Program Files\OrangeSpace-phase1-'+[Guid]::NewGuid().ToString('N')
$pipeName='OrangeSpace-phase1-'+[Guid]::NewGuid().ToString('N')
$taskName=$pipeName
$events=New-Object System.Collections.Generic.List[object]
$before=Service-Baseline
$before | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $SourceDirectory 'phase1_services_before.json')
$taskCreated=$false;$taskGone=$false;$rootGone=$false;$processesGone=$false;$controllerResult=$null;$nativeTaskExit=$null
$pipe=$null;$bootstrap=$null;$failure=$false;$heldController=$null
try {
 if(Test-Path -LiteralPath $root){throw 'fresh fixture root collision'}
 if($Mode -eq 'Accept' -and $null -ne (Get-Service -Name OrangeSpaceFoundation -ErrorAction SilentlyContinue)){throw 'existing foundation service will not be overwritten'}
 $files=@{'phase1_client.exe'=$ClientSha256;'phase1_controller.exe'=$ControllerSha256;'nodes.json'=$CatalogSha256}
 if($Mode -eq 'Accept'){$files['OrangeSpaceFoundation.exe']=$ServiceSha256;$files['sing-box.exe']=$HelperSha256
  if($HelperSha256 -cne '8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9'){throw 'helper not approved official hash'}
 }
 foreach($f in $files.Keys){Verify-Hash (Join-Path $SourceDirectory $f) $files[$f]}
 New-Item -ItemType Directory -Path $root | Out-Null
 $acl=New-Object System.Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
 Set-Acl -LiteralPath $root -AclObject $acl
 foreach($f in $files.Keys){Copy-Item -LiteralPath (Join-Path $SourceDirectory $f) -Destination (Join-Path $root $f);Verify-Hash (Join-Path $root $f) $files[$f]}
 if($Mode -eq 'Accept'){
  # First provision ONLY in a new root; never repair/reset an existing ledger.
  $state=Join-Path $root 'service-state.json'
  $stream=[IO.File]::Open($state,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$bytes=[Text.Encoding]::UTF8.GetBytes('{"schema":1,"sandboxes":[]}');$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  $private=New-Object System.Security.AccessControl.FileSecurity
  $private.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Set-Acl -LiteralPath $state -AclObject $private
 }
 # Receive memory-only bootstrap BEFORE launching any privileged fixture action.
 $bootstrap=Read-Frame ([Console]::OpenStandardInput()) 20000
 $controller=Join-Path $root 'phase1_controller.exe'
 $action=New-ScheduledTaskAction -Execute $controller -Argument ('"'+$root+'" "'+$pipeName+'" --'+$Mode.ToLowerInvariant()) -WorkingDirectory $root
 $principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null;$taskCreated=$true
 Start-ScheduledTask -TaskName $taskName
 $pipe=New-Object IO.Pipes.NamedPipeClientStream('.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
 $pipe.Connect(25000)
 [uint32]$serverPid=0
 if(-not [Phase1PipeNative]::GetNamedPipeServerProcessId($pipe.SafePipeHandle.DangerousGetHandle(),[ref]$serverPid)){throw 'cannot authenticate private pipe server'}
 $heldController=[Diagnostics.Process]::GetProcessById([int]$serverPid)
 # Open and hold actual process object; never kill by an unverified reusable PID.
 $null=$heldController.Handle
 if($heldController.MainModule.FileName -cne $controller -or $heldController.SessionId -ne 2 -or $heldController.HasExited){throw 'private pipe server identity mismatch'}
 if($Fault -eq 'BadBootstrap'){$bad=[Text.Encoding]::UTF8.GetBytes('{}');Send-Frame $pipe $bad}
 elseif($Fault -eq 'TruncatedBootstrap'){$head=[BitConverter]::GetBytes([uint32]10);$pipe.Write($head,0,4);$pipe.WriteByte(123);$pipe.Flush()}
 else{Send-Frame $pipe $bootstrap}
 [Array]::Clear($bootstrap,0,$bootstrap.Length);$bootstrap=$null
 while($null -eq $controllerResult){
  $message=Read-Frame $pipe 300000
  try{$value=[Text.Encoding]::UTF8.GetString($message)|ConvertFrom-Json}finally{[Array]::Clear($message,0,$message.Length)}
  if($value.schema -ne 1 -or $value.kind -notin @('pass','wait','controller_fault','client_result','bootstrap_result','controller_result')){throw 'invalid typed evidence event'}
  $events.Add($value)
  if($value.kind -eq 'controller_result'){$controllerResult=$value}
 }
 if(-not $heldController.WaitForExit(15000)){throw 'controller native exit timeout'}
 $nativeTaskExit=$heldController.ExitCode
 if($Fault -eq 'None' -and ($nativeTaskExit -ne 0 -or -not $controllerResult.ok)){throw 'native fixture did not pass'}
 if($Fault -ne 'None' -and ($nativeTaskExit -eq 0 -or $controllerResult.ok)){throw 'fault was not rejected'}
} catch {$failure=$true} finally {
 if($null -ne $bootstrap){[Array]::Clear($bootstrap,0,$bootstrap.Length)}
 if($null -ne $pipe){$pipe.Dispose()}
 if($null -ne $heldController){
  # Closing the bootstrap pipe lets controller unwind bounded native cleanup.
  # Forced termination is last resort; a surviving SCM registration fails cleanup.
  if(-not $heldController.HasExited -and -not $heldController.WaitForExit(45000)){$heldController.Kill();$null=$heldController.WaitForExit(15000)}
  if($heldController.HasExited -and $null -eq $nativeTaskExit){$nativeTaskExit=$heldController.ExitCode}
  $heldController.Dispose()
 }
 if($taskCreated){
  $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if($null -ne $task -and $task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName}
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
 }
 $taskGone=$null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
 $owned=@(Get-CimInstance Win32_Process | Where-Object { $null -ne $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) })
 $processesGone=$owned.Count -eq 0
 $ownedServiceGone=$Mode -eq 'Selftest' -or $null -eq (Get-Service -Name OrangeSpaceFoundation -ErrorAction SilentlyContinue)
 # Never erase a live fixture or unknown ledger after a cleanup failure.
 if($taskGone -and $processesGone -and $ownedServiceGone -and (Test-Path -LiteralPath $root)){Remove-Item -Recurse -Force -LiteralPath $root}
 $rootGone=-not(Test-Path -LiteralPath $root)
 $after=Service-Baseline
 $after | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $SourceDirectory 'phase1_services_after.json')
 $configBefore=@($before|Select-Object Name,StartMode,PathName,StartName,ServiceType)|ConvertTo-Json -Depth 6
 $configAfter=@($after|Select-Object Name,StartMode,PathName,StartName,ServiceType)|ConvertTo-Json -Depth 6
 $configUnchanged=$configBefore -ceq $configAfter
 $runtimeUnchanged=($before|ConvertTo-Json -Depth 6) -ceq ($after|ConvertTo-Json -Depth 6)
 # All differences retained, including ordinary OS activation. Never stop builtins.
 $runtimeChanges=@(Compare-Object @($before|ForEach-Object{$_|ConvertTo-Json -Compress}) @($after|ForEach-Object{$_|ConvertTo-Json -Compress}))
 $report=[ordered]@{schema=1;kind='outer_result';ok=(-not $failure -and $taskGone -and $processesGone -and $rootGone -and $ownedServiceGone -and $configUnchanged -and $runtimeUnchanged);mode=$Mode;fault=$Fault;fixture_root=$root;fixture_task=$taskName;native_controller_exit=$nativeTaskExit;task_removed=$taskGone;processes_removed=$processesGone;root_removed=$rootGone;owned_service_removed=$ownedServiceGone;service_configuration_unchanged=$configUnchanged;service_runtime_unchanged=$runtimeUnchanged;service_runtime_changes=$runtimeChanges;events=@($events.ToArray());full_acceptance=$false;os_b_covered=$false;browser_allowed=$false}
 $report|ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $SourceDirectory 'phase1_result.json')
 $report|ConvertTo-Json -Depth 12 -Compress
}
if(-not $report.ok){exit 1}
