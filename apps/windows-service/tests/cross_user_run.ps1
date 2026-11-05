param([Parameter(Mandatory=$true)][string]$Binary,[Parameter(Mandatory=$true)][string]$Sha256)
$ErrorActionPreference='Stop'
if((Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash -ne $Sha256){throw 'upload hash mismatch'}
$token=[Guid]::NewGuid().ToString('N')
$root="C:\Program Files\OrangeSpace-cross-user-$token"
$task="OrangeSpace-cross-user-$token"
$exe="$root\cross_user_fixture.exe"
function Baseline { @(Get-CimInstance Win32_Service | Sort-Object Name | Select-Object Name,State,StartMode,ProcessId,PathName) }
$before=Baseline
$before | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -LiteralPath "$Binary.before.json"
$result=$null
$taskCreated=$false
try {
 if(Test-Path -LiteralPath $root){throw 'owned root collision'}
 New-Item -ItemType Directory -Path $root | Out-Null
 $acl=New-Object System.Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
 Set-Acl -LiteralPath $root -AclObject $acl
 Copy-Item -LiteralPath $Binary -Destination $exe
 if((Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash -ne $Sha256){throw 'staging hash mismatch'}
 $action=New-ScheduledTaskAction -Execute $exe -Argument ('"'+$root+'"') -WorkingDirectory $root
 $principal=New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
 $taskCreated=$true
 Start-ScheduledTask -TaskName $task
 $deadline=(Get-Date).AddSeconds(130)
 do { Start-Sleep -Milliseconds 250; $state=(Get-ScheduledTask -TaskName $task).State } while($state -eq 'Running' -and (Get-Date) -lt $deadline)
 if($state -eq 'Running'){throw 'bounded native fixture timeout; preserve owned root for explicit recovery'}
 if(-not(Test-Path -LiteralPath "$root\result.json")){throw "native result absent, task result $((Get-ScheduledTaskInfo -TaskName $task).LastTaskResult)"}
 $result=Get-Content -Raw -LiteralPath "$root\result.json" | ConvertFrom-Json
 $result | Add-Member NoteProperty fixture_root $root
 $result | Add-Member NoteProperty fixture_task $task
 $result | Add-Member NoteProperty executable_sha256 $Sha256
} finally {
 if($taskCreated){Unregister-ScheduledTask -TaskName $task -Confirm:$false}
 $taskAbsent=$null -eq (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)
 $processes=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $exe })
 $after=Baseline
 $after | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -LiteralPath "$Binary.after.json"
 $diff=@(Compare-Object ($before | ConvertTo-Json -Depth 4) ($after | ConvertTo-Json -Depth 4))
 $servicesUnchanged=$diff.Count -eq 0
 # Do not destroy diagnostic ownership records or an unclean profile/account.
 $rootRemoved=$false
 if($null -ne $result -and $result.account_removed -and $result.profile_removed -and $processes.Count -eq 0 -and $taskAbsent){Remove-Item -Recurse -Force -LiteralPath $root;$rootRemoved=-not(Test-Path -LiteralPath $root)}
 if($null -ne $result){
  $result | Add-Member NoteProperty task_removed $taskAbsent
  $result | Add-Member NoteProperty processes_removed ($processes.Count -eq 0)
  $result | Add-Member NoteProperty root_removed $rootRemoved
  $result | Add-Member NoteProperty services_unchanged $servicesUnchanged
  $result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath "$Binary.result.json"
  $result | ConvertTo-Json -Depth 8 -Compress
 }
 if(-not $taskAbsent){throw 'owned task remains'}
 if($processes.Count -ne 0){throw 'owned executable processes remain; no PID-only termination attempted'}
}
if($null -eq $result -or -not $result.ok -or -not $rootRemoved -or -not $servicesUnchanged){throw 'native acceptance incomplete; consult exact JSON and service baseline files'}
