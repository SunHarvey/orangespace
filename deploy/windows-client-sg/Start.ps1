. (Join-Path $PSScriptRoot 'Common.ps1')
try {
    if (Test-Admin) { Write-Host 'start-refused: run OrangeSpace from the ordinary-user desktop, not as Administrator.'; exit 1 }
    Assert-Policy $script:Root
    Assert-InstallManifest $script:Root
    foreach ($name in @('OrangeSpace.exe','platform.json','nodes.json','sing-box.exe')) { Assert-Policy (Join-Path $script:Root $name) }
    $manager = [OrangeInstallNative]::OpenLocalManager(1)
    [OrangeInstallNative]::Need($manager -ne [IntPtr]::Zero)
    $service = [IntPtr]::Zero
    try {
        $service = Open-OwnedService $manager 5
        if ($service -eq [IntPtr]::Zero -or ([OrangeInstallNative]::ReadStatus($service)).State -ne 4) { throw 'service-not-running' }
    } finally {
        if ($service -ne [IntPtr]::Zero) { $null = [OrangeInstallNative]::CloseServiceHandle($service) }
        $null = [OrangeInstallNative]::CloseServiceHandle($manager)
    }
    Start-Process -FilePath (Join-Path $script:Root 'OrangeSpace.exe') -WorkingDirectory $script:Root
    exit 0
} catch { Write-Host 'start-failed: installation/service unavailable; do not manually run a helper. Ask the installer administrator.'; exit 1 }
