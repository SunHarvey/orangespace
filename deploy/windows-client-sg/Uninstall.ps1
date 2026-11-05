. (Join-Path $PSScriptRoot 'Common.ps1')
$stage = 'preflight'
$manager = [IntPtr]::Zero
$service = [IntPtr]::Zero
$process = $null
try {
    if (Invoke-Elevation $PSCommandPath) { exit 0 }
    Assert-Policy $script:Root
    Assert-InstallManifest $script:Root
    $rows = Read-Inventory $script:Root
    Assert-Inventory $script:Root $rows $true
    # Never delete/stop an unknown same-name Service. Preserve AppData, SQLite,
    # browser Profiles, private generation ledger and every remote Linux file.
    $manager = Open-ServiceManager
    $service = Open-OwnedService $manager
    if ($service -ne [IntPtr]::Zero) {
        $status = [OrangeInstallNative]::ReadStatus($service)
        if ($status.State -eq 4) {
            $stage = 'retain-exact-service-process'
            $process = [Diagnostics.Process]::GetProcessById([int]$status.Pid)
            $null = $process.Handle
            if ($process.MainModule.FileName -cne (Join-Path $script:Root 'OrangeSpaceSinglePrototype.exe')) { throw 'process-image-mismatch' }
            $again = [OrangeInstallNative]::ReadStatus($service)
            if ($again.State -ne 4 -or $again.Pid -ne $status.Pid -or $process.HasExited) { throw 'process-race' }
            $stage = 'bounded-service-stop'
            $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(36)
            try { [OrangeInstallNative]::Need([OrangeInstallNative]::ControlService($service,1,$buffer)) }
            finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
            $null = Wait-ServiceState $service 1
            if (!$process.WaitForExit(30000)) { throw 'exact-process-exit-unknown' }
        } elseif ($status.State -ne 1) { throw 'service-transition-refused' }
    }
    $stage = 'client-exit-check'
    # Observation only: no name-based kill, task removal, firewall reset or
    # unrelated Service manipulation. An open GUI requires the user to close it.
    foreach ($p in @(Get-CimInstance Win32_Process)) {
        if ($p.ExecutablePath -and $p.ExecutablePath.StartsWith($script:Root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'close-owned-client-first' }
    }
    if (Test-Path -LiteralPath $script:Link) {
        $null = Assert-Ordinary $script:Link
        $shell = New-Object -ComObject WScript.Shell
        $desktopLink = $shell.CreateShortcut($script:Link)
        if ($desktopLink.TargetPath -cne (Join-Path $script:Root 'OrangeSpace.exe') -or $desktopLink.Arguments) { throw 'foreign-shortcut-retained' }
    }
    $stage = 'delete-owned-service'
    if ($service -ne [IntPtr]::Zero) {
        [OrangeInstallNative]::Need([OrangeInstallNative]::DeleteService($service))
        $null = [OrangeInstallNative]::CloseServiceHandle($service)
        $service = [IntPtr]::Zero
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $probe = [OrangeInstallNative]::OpenServiceW($manager,$script:ServiceName,4)
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($probe -eq [IntPtr]::Zero -and $errorCode -eq 1060) { break }
        if ($probe -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($probe) }
        if ($watch.Elapsed.TotalSeconds -ge 30) { throw 'service-delete-pending' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    $stage = 'delete-owned-runtime'
    Assert-Inventory $script:Root $rows $true
    # Exact closed-inventory leaves only; never recursive deletion through an
    # unknown junction or any personal/state directory.
    $tree = @(Get-Tree $script:Root)
    foreach ($entry in @($tree | Where-Object { !$_.PSIsContainer })) { Remove-Item -LiteralPath $entry.FullName -Force }
    foreach ($entry in @($tree | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length } -Descending)) { [IO.Directory]::Delete($entry.FullName,$false) }
    [IO.Directory]::Delete($script:Root,$false)
    if (Test-Path -LiteralPath $script:Link) { Remove-Item -LiteralPath $script:Link -Force }
    if ((Test-Path -LiteralPath $script:Root) -or (Test-Path -LiteralPath $script:Link)) { throw 'delete-readback-failed' }
    Write-Host 'uninstall-complete: user Profile/SQLite and private generation ledger preserved. No system firewall/trust reset performed.'
    exit 0
} catch {
    Write-Host ('uninstall-failed:'+$stage+'; close OrangeSpace first. Unknown processes/data retained.')
    exit 1
} finally {
    if ($null -ne $process) { $process.Dispose() }
    if ($service -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($service) }
    if ($manager -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($manager) }
}
