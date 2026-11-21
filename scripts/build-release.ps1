param(
    [Parameter(Mandatory = $true)][string]$Rootfs,   # orangespace-rootfs.tar.gz from linux-desktop/wsl/build-rootfs
    [Parameter(Mandatory = $true)][string]$Image,    # desktop-image.tar from linux-desktop/guest/build-image --archive
    [Parameter(Mandatory = $true)][string]$Trust,    # this deployment's trust files (platform.json, catalog.json, CAs)
    [string]$Version = '',                           # x.y.z; default: the CMake project version
    [string]$Output = '',                            # default: build\release
    [switch]$SkipBuild                               # use the existing Release build of the client
)
# Builds the OrangeSpace installer (Inno Setup 6.7):
#   1. builds and tests the Windows client (scripts\build-windows.ps1) unless -SkipBuild;
#   2. checks the root filesystem and desktop image against their .sha256 files;
#   3. stages OrangeSpace.exe, trust\, system\ (with release.json) and licenses\;
#   4. runs ISCC on deploy\windows\orangespace.iss.
# The release revision is the one baked into the root filesystem
# (/opt/orangespace/REVISION); the client compares it with each user's
# distribution to decide on an upgrade.
$ErrorActionPreference = 'Stop'
$Repository = Split-Path -Parent $PSScriptRoot
$Utf8 = New-Object System.Text.UTF8Encoding $false

function Fail($message) { throw "build-release: $message" }

# stdout of tar.exe; its warnings on stderr are dropped (Windows PowerShell
# would otherwise turn them into terminating errors under 'Stop'). bsdtar exits
# 1 on the root filesystem's unnamed top entry even when the member it was
# asked for came out whole, so callers check the text, not the exit code.
function Tar-Out([string[]]$arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & "$env:SystemRoot\System32\tar.exe" @arguments 2>$null } finally { $ErrorActionPreference = $saved }
    return @{ Text = $out }
}

function Check-Sha256($path) {
    $file = "$path.sha256"
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { Fail "missing $file" }
    $expected = ((Get-Content -LiteralPath $file -TotalCount 1) -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { Fail "$path does not match $file" }
    return $actual
}

foreach ($p in @($Rootfs, $Image)) { if (!(Test-Path -LiteralPath $p -PathType Leaf)) { Fail "missing $p" } }
foreach ($p in @("$Rootfs.packages.tsv", "$Image.packages.tsv", "$Image.base-image.txt")) {
    if (!(Test-Path -LiteralPath $p -PathType Leaf)) { Fail "missing $p" }
}
foreach ($p in @('platform.json', 'catalog.json')) {
    if (!(Test-Path -LiteralPath (Join-Path $Trust $p) -PathType Leaf)) { Fail "the trust folder has no $p" }
}
if (!$Version) {
    $line = Select-String -LiteralPath (Join-Path $Repository 'CMakeLists.txt') -Pattern 'project\(OrangeSpace VERSION ([0-9.]+)'
    $Version = $line.Matches[0].Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Fail "version must be x.y.z, not '$Version'" }
if (!$Output) { $Output = Join-Path $Repository 'build\release' }
$Iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
if (!(Test-Path -LiteralPath $Iscc)) { Fail "Inno Setup 6 is not installed ($Iscc)" }

if (!$SkipBuild) {
    & (Join-Path $PSScriptRoot 'build-windows.ps1') -Configuration Release
    if ($LASTEXITCODE -ne 0) { Fail 'client build failed' }
}
$Exe = Join-Path $Repository 'build\windows\apps\windows-client\Release\OrangeSpace.exe'
if (!(Test-Path -LiteralPath $Exe -PathType Leaf)) { Fail "no client build at $Exe" }

$RootfsSha = Check-Sha256 $Rootfs
$ImageSha = Check-Sha256 $Image

# The revision inside the root filesystem.
$Revision = ''
foreach ($member in @('./opt/orangespace/REVISION', 'opt/orangespace/REVISION')) {
    $r = Tar-Out @('-xzOf', $Rootfs, $member)
    if ($r.Text) { $Revision = (@($r.Text)[0]).Trim(); break }
}
if ($Revision -notmatch '^[!-~]{1,64}$') { Fail "cannot read a revision from $Rootfs" }
# The image must carry the tag the guest runs.
$index = Tar-Out @('-xOf', $Image, 'index.json')
if (($index.Text -join '') -notmatch 'orangespace/desktop:current') { Fail "$Image is not the desktop image (no orangespace/desktop:current)" }

$Payload = Join-Path $Output 'payload'
if (Test-Path -LiteralPath $Payload) { Remove-Item -LiteralPath $Payload -Recurse -Force }
foreach ($d in @('trust', 'system', 'licenses')) { New-Item -ItemType Directory -Path (Join-Path $Payload $d) -Force | Out-Null }
Copy-Item -LiteralPath $Exe -Destination $Payload
Get-ChildItem -LiteralPath $Trust -File | Where-Object { $_.Extension -in '.json', '.crt', '.pem' } |
    Copy-Item -Destination (Join-Path $Payload 'trust')
Copy-Item -LiteralPath $Rootfs -Destination (Join-Path $Payload 'system\orangespace-rootfs.tar.gz')
Copy-Item -LiteralPath $Image -Destination (Join-Path $Payload 'system\desktop-image.tar')
$release = '{"schema":1,"revision":"' + $Revision + '","rootfs":"orangespace-rootfs.tar.gz","rootfs_sha256":"' + $RootfsSha +
           '","image":"desktop-image.tar","image_sha256":"' + $ImageSha + '"}'
[System.IO.File]::WriteAllText((Join-Path $Payload 'system\release.json'), $release, $Utf8)

$Licenses = Join-Path $Payload 'licenses'
Copy-Item -LiteralPath "$Rootfs.packages.tsv" -Destination (Join-Path $Licenses 'rootfs-packages.tsv')
Copy-Item -LiteralPath "$Image.packages.tsv" -Destination (Join-Path $Licenses 'desktop-image-packages.tsv')
Copy-Item -LiteralPath "$Image.base-image.txt" -Destination (Join-Path $Licenses 'desktop-image-base.txt')
Copy-Item -LiteralPath (Join-Path $Repository 'deploy\windows\SOURCES.md') -Destination $Licenses
& python -I (Join-Path $PSScriptRoot 'rust_notices.py') (Join-Path $Licenses 'rust-crates.txt')
if ($LASTEXITCODE -ne 0) { Fail 'collecting Rust license notices failed' }

& $Iscc /Qp "/DAppVersion=$Version" "/DPayload=$Payload" "/DOutputDir=$Output" (Join-Path $Repository 'deploy\windows\orangespace.iss')
if ($LASTEXITCODE -ne 0) { Fail 'ISCC failed' }
$Setup = Join-Path $Output "OrangeSpace-Setup-$Version.exe"
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Setup).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$Setup.sha256", "$hash  OrangeSpace-Setup-$Version.exe`n", $Utf8)
"built $Setup (revision $Revision)"
"sha256 $hash"
