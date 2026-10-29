#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$BuildDirectory,
    [string]$Python = 'python'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows x64 + VS2022/SDK are required' }
$Repo = Split-Path -Parent $PSScriptRoot
$Archive = (Resolve-Path -LiteralPath $Archive).Path
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
if (Test-Path -LiteralPath $BuildDirectory) { throw 'Use a fresh, nonexistent BuildDirectory; no stale build or runtime merge is allowed' }
foreach ($Command in @($Python, 'cmake', 'ctest', 'dumpbin')) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Missing $Command; use an x64 Native Tools Command Prompt for VS2022"
    }
}
$Package = Join-Path $BuildDirectory 'cef-package'
# No network calls. Obtain the exact locked archive separately and opt in to
# its download explicitly. Python checks size, SHA-1 and pinned SHA-256 before extraction.
& $Python (Join-Path $PSScriptRoot 'cef_package.py') --archive $Archive --extract-to $Package
if ($LASTEXITCODE -ne 0) { throw 'CEF archive verification/extraction failed' }
$CMakeBuild = Join-Path $BuildDirectory 'build'
& cmake -S (Join-Path $Repo 'apps/windows-client/cef') -B $CMakeBuild -G 'Visual Studio 17 2022' -A x64 "-DCEF_ROOT=$Package" -DUSE_SANDBOX=ON -DBUILD_TESTING=ON
if ($LASTEXITCODE -ne 0) { throw 'CEF configure failed' }
& cmake --build $CMakeBuild --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw 'CEF Windows compile/link failed' }
# Only portable policy tests run: NEVER invoke client.exe or a CEF sample.
& ctest --test-dir $CMakeBuild -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'CEF policy tests failed' }
$Output = Join-Path $CMakeBuild 'compile-only/Release'
foreach ($Name in @('client.dll', 'client.exe')) {
    $File = Join-Path $Output $Name
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { throw "Missing $Name" }
    if ((Get-Item -LiteralPath $File).Length -eq 0) { throw "Empty $Name" }
}
$Exports = & dumpbin /nologo /exports (Join-Path $Output 'client.dll')
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect client.dll exports' }
if (-not ($Exports -match '\bRunWinMain\b')) { throw 'Missing exact RunWinMain export' }
$Original = (Get-FileHash -LiteralPath (Join-Path $Package 'Release/bootstrap.exe') -Algorithm SHA256).Hash
$Copied = (Get-FileHash -LiteralPath (Join-Path $Output 'client.exe') -Algorithm SHA256).Hash
if ($Original -ne $Copied) { throw 'Staged bootstrap differs from verified CEF package' }
Write-Output "Compile/link and policy checks passed: $Output"
Write-Output 'Compile-only artifacts, NOT a runnable browser package. No CEF runtime, sandbox launch, WFP/DNS, or browser behavior was tested.'
