param([Parameter(Mandatory = $true)][string]$TestBinary)
$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path $TestBinary).Path
# OpenSSH runs in session 0; these non-GUI tests require the logged-on user's token.
# A disconnected RDP session suffices. Never request elevation or save credentials.
$Work = Join-Path (Split-Path $Binary) ('native-run-' + [guid]::NewGuid().ToString('N'))
$TaskName = 'OrangeSpace-Foundation-Test-' + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $Work | Out-Null
$Runner = Join-Path $Work 'run.ps1'
$Output = Join-Path $Work 'output.txt'
$Result = Join-Path $Work 'exit.txt'
$EscapedBinary = $Binary.Replace("'", "''")
$EscapedOutput = $Output.Replace("'", "''")
$EscapedResult = $Result.Replace("'", "''")
@"
`$ErrorActionPreference = 'Stop'
try {
    & '$EscapedBinary' *> '$EscapedOutput'
    `$Code = `$LASTEXITCODE
} catch {
    `$_ | Out-File '$EscapedOutput' -Append
    `$Code = 1
}
Set-Content -Path '$EscapedResult' -Value `$Code
"@ | Set-Content $Runner
$Registered = $false
try {
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Runner`""
    $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    $Settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 40)
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Principal $Principal -Settings $Settings | Out-Null
    $Registered = $true
    Start-ScheduledTask -TaskName $TaskName
    $Deadline = (Get-Date).AddSeconds(50)
    while (!(Test-Path $Result) -and (Get-Date) -lt $Deadline) { Start-Sleep -Milliseconds 200 }
    if (!(Test-Path $Result)) { throw 'Interactive test did not finish; log on as this user before running.' }
    Get-Content $Output
    $Code = [int](Get-Content $Result)
    if ($Code -ne 0) { throw "Native test failed with exit $Code" }
} finally {
    if ($Registered) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'Temporary test task still exists' }
    }
    Remove-Item $Work -Recurse -Force
}
