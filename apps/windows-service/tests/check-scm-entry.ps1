param([Parameter(Mandatory = $true)][string]$ServiceBinary)
$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path $ServiceBinary).Path
# No SCM registration, privilege elevation, or service installation occurs here.
$Process = Start-Process -FilePath $Binary -PassThru -Wait -WindowStyle Hidden
if ($Process.ExitCode -ne 1063) { throw "Expected ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063), got $($Process.ExitCode)" }
$Process = Start-Process -FilePath $Binary -ArgumentList '--console' -PassThru -Wait -WindowStyle Hidden
if ($Process.ExitCode -ne 87) { throw "Expected ERROR_INVALID_PARAMETER (87), got $($Process.ExitCode)" }
Write-Output 'SCM-only entry and unsupported-argument denial passed (no service installed)'
