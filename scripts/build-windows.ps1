param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
# Builds the Windows client (OrangeSpace.exe, orangespace-wsl, orangespace-sandbox)
# and runs its tests. The client's app-private HTTPS comes from the Rust
# orangespace-https static library, built here first.
$ErrorActionPreference = 'Stop'
$Repository = Split-Path -Parent $PSScriptRoot
Push-Location $Repository
try {
    & cargo build --locked --release --jobs 1 -p orangespace-https
    if ($LASTEXITCODE -ne 0) { throw 'orangespace-https build failed' }
    $HttpsLibrary = Join-Path $Repository 'target/release/orangespace_https.lib'
    if (!(Test-Path -LiteralPath $HttpsLibrary -PathType Leaf)) { throw 'orangespace_https.lib is absent' }
    & cmake -S . -B build/windows -A x64 "-DORANGESPACE_HTTPS_LIBRARY=$HttpsLibrary"
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
    & cmake --build build/windows --config $Configuration --parallel 1
    if ($LASTEXITCODE -ne 0) { throw 'Windows client build failed' }
    & ctest --test-dir build/windows -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Windows client tests failed' }
} finally {
    Pop-Location
}
