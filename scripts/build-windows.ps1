param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$Repository = Split-Path -Parent $PSScriptRoot
Push-Location $Repository
try {
    & cargo build --locked --release --jobs 1 -p orangespace-broker -p orangespace-runtime
    if ($LASTEXITCODE -ne 0) { throw 'Rust broker/runtime build failed' }
    $RuntimeLibrary = Join-Path $Repository 'target/release/orangespace_runtime.lib'
    if (!(Test-Path -LiteralPath $RuntimeLibrary -PathType Leaf)) { throw 'Required service runtime static library is absent' }
    & cmake -S . -B build/windows -A x64 "-DORANGESPACE_RUNTIME_LIBRARY=$RuntimeLibrary"
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
    & cmake --build build/windows --config $Configuration --parallel 1
    if ($LASTEXITCODE -ne 0) { throw 'Windows client build failed' }
    & ctest --test-dir build/windows -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Client model checks failed' }
    $Output = Join-Path $Repository 'artifacts/windows-dev'
    New-Item -ItemType Directory -Force -Path $Output | Out-Null
    Copy-Item "build/windows/apps/windows-client/$Configuration/OrangeSpace.exe" $Output
    Copy-Item "build/windows/apps/windows-client/$Configuration/OrangeSpaceLogin.exe" $Output
    Copy-Item "build/windows/apps/windows-service/$Configuration/OrangeSpaceService.exe" $Output
    Copy-Item 'target/release/orangespace-broker.exe' $Output
    Copy-Item "build/windows/drivers/wfp-baseline/$Configuration/orangespace-wfp-baseline.exe" $Output
    Write-Host "Development manager created at $Output. Browser networking remains blocked."
} finally {
    Pop-Location
}
