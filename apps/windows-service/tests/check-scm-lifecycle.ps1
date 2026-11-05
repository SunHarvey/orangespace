param([Parameter(Mandatory=$true)][string]$SourceBinary)
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated test token required' }
$name = 'OrangeSpaceFoundation'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Refuse to replace existing service' }
$root = Join-Path $env:ProgramFiles ('OrangeSpace-ServiceTest-' + [guid]::NewGuid().ToString('N'))
$created = $false
try {
 New-Item -ItemType Directory -Path $root | Out-Null
 $acl = New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath $root -AclObject $acl
 $binary = Join-Path $root 'OrangeSpaceService.exe'
 Copy-Item -LiteralPath $SourceBinary -Destination $binary
 $before = (Get-FileHash -Algorithm SHA256 -LiteralPath $SourceBinary).Hash
 $after = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash
 if ($before -ne $after) { throw 'Transfer/copy hash mismatch' }
 Write-Output ('Candidate SHA256=' + $after)
 New-Service -Name $name -BinaryPathName ('"' + $binary + '"') -StartupType Manual -DisplayName 'OrangeSpace isolated foundation test' | Out-Null
 $created = $true
 & sc.exe config $name obj= LocalSystem type= own start= demand | Out-Null
 if ($LASTEXITCODE -ne 0) { throw 'Explicit service identity configuration failed' }
 $registration = Get-CimInstance Win32_Service -Filter "Name='$name'"
 if ($registration.StartName -ne 'LocalSystem' -or $registration.PathName -ne ('"' + $binary + '"')) { throw 'Unexpected service registration' }
 Start-Service -Name $name
 $service = Get-Service -Name $name
 $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(10))
 Start-Sleep -Seconds 3
 $registration = Get-CimInstance Win32_Service -Filter "Name='$name'"
 if ($registration.State -ne 'Running' -or !$registration.ProcessId) { throw 'SCM service did not remain Running' }
 $process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $registration.ProcessId)
 if ($process.ExecutablePath -ne $binary) { throw 'SCM started wrong executable' }
 Write-Output ('SCM Running PID=' + $registration.ProcessId + ' Path=' + $process.ExecutablePath)
 Stop-Service -Name $name
 $service = Get-Service -Name $name
 $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
 if (Get-Process -Id $registration.ProcessId -ErrorAction SilentlyContinue) { throw 'Service process remains after stop' }
 Write-Output 'SCM start/stop passed. Disconnected desktop: no active WTS endpoint or browser validation claimed.'
} finally {
 if ($created) {
  Stop-Service -Name $name -ErrorAction SilentlyContinue
  & sc.exe delete $name | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'SCM cleanup failed' }
  if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Service still registered after delete' }
 }
 if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
 if (Test-Path -LiteralPath $root) { throw 'Protected fixture remains' }
 Write-Output 'CLEANUP VERIFIED: no test service or protected fixture remains'
}
