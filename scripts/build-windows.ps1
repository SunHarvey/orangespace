param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$Repository = Split-Path -Parent $PSScriptRoot
Push-Location $Repository
try {
    & cargo build --locked --release -p orangespace-broker
    if ($LASTEXITCODE -ne 0) { throw 'Rust broker build failed' }
    & cmake -S . -B build/windows -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
    & cmake --build build/windows --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Windows client build failed' }
    & ctest --test-dir build/windows -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Client model checks failed' }
    $Output = Join-Path $Repository 'artifacts/windows-dev'
    New-Item -ItemType Directory -Force -Path $Output | Out-Null
    Copy-Item "build/windows/apps/windows-client/$Configuration/OrangeSpace.exe" $Output
    Copy-Item 'target/release/orangespace-broker.exe' $Output
    Copy-Item "build/windows/drivers/wfp-baseline/$Configuration/orangespace-wfp-baseline.exe" $Output
    Write-Host "Development manager created at $Output. Browser networking remains blocked."
} finally {
    Pop-Location
}
