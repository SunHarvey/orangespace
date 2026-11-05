param(
    [Parameter(Mandatory=$true)][string]$BuildRoot,
    [Parameter(Mandatory=$true)][string]$Helper,
    [Parameter(Mandatory=$true)][string]$Output,
    [switch]$Offline
)
. (Join-Path $PSScriptRoot 'Common.ps1')
if ($env:OS -ne 'Windows_NT') { throw 'Native Windows/MSVC build only; GNU cross-link is not native acceptance' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (!(Test-Path -LiteralPath (Join-Path $repo 'scripts/build-windows.ps1'))) { throw 'Repository build prerequisite absent' }
# Freeze every caller-supplied path before checks or any location change.
function Resolve-BuildInput([string]$Value) {
    $provider = $null
    $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Value, [ref]$provider, [ref]$drive)
    if (!$provider -or $provider.Name -cne 'FileSystem') { throw 'Build inputs require the FileSystem provider' }
    return $resolved
}
$BuildRoot = Resolve-BuildInput $BuildRoot
$Helper = Resolve-BuildInput $Helper
$Output = Resolve-BuildInput $Output
if (Test-Path -LiteralPath $BuildRoot) { throw 'Fresh build directory required' }
if (Test-Path -LiteralPath $Output) { throw 'Fresh package target required' }
$null = Assert-Ordinary $Helper
if ((Get-FileHash -LiteralPath $Helper).Hash.ToLowerInvariant() -cne $script:HelperHash) { throw 'Official Windows helper 1.14.4 hash mismatch' }
New-Item -ItemType Directory -Path $BuildRoot -ErrorAction Stop | Out-Null
$rust = Join-Path $BuildRoot 'rust'
$native = Join-Path $BuildRoot 'native'
Push-Location $repo
try {
    # Same cargo -> runtime -> root CMake chain as scripts/build-windows.ps1,
    # but all outputs are fresh and only the five reviewed programs are packaged.
    $offlineArguments = @()
    if ($Offline) { $offlineArguments = @('--offline') }
    & cargo build --locked --release --jobs 1 @offlineArguments --target-dir $rust -p orangespace-broker -p orangespace-runtime
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    $runtime = Join-Path $rust 'release/orangespace_runtime.lib'
    if (!(Test-Path -LiteralPath $runtime -PathType Leaf)) { throw 'Native MSVC runtime archive required' }
    & cmake -S $repo -B $native -A x64 "-DORANGESPACE_RUNTIME_LIBRARY=$runtime" -DORANGESPACE_WITH_CEF=OFF
    if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
    & cmake --build $native --config Release --parallel 1 --target OrangeSpace OrangeSpaceLogin OrangeSpaceService
    if ($LASTEXITCODE -ne 0) { throw 'Native program build failed' }
    $staging = Join-Path $BuildRoot 'exact-programs'
    New-Item -ItemType Directory -Path $staging | Out-Null
    foreach ($name in @('OrangeSpace.exe','OrangeSpaceLogin.exe')) {
        Copy-Item -LiteralPath (Join-Path $native ('apps/windows-client/Release/' + $name)) -Destination $staging
    }
    Copy-Item -LiteralPath (Join-Path $native 'apps/windows-service/Release/OrangeSpaceService.exe') -Destination $staging
    Copy-Item -LiteralPath (Join-Path $rust 'release/orangespace-broker.exe') -Destination $staging
    Copy-Item -LiteralPath $Helper -Destination (Join-Path $staging 'sing-box.exe')
    & python (Join-Path $PSScriptRoot 'package.py') create $staging $Output
    if ($LASTEXITCODE -ne 0) { throw 'Package verification failed' }
} finally { Pop-Location }
