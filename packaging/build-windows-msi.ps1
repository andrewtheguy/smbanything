# Build the Windows native package for x86-64: dist\smbanything-windows-x86_64.msi.
#
# Installed by Windows Installer under %ProgramFiles%\smbanything with bin on the machine PATH
# — and nothing else, like the .deb, .rpm and .pkg: no service, no config. The Wintun driver
# sits beside the exe, where --smb-tun looks for it:
#
#   C:\Program Files\smbanything\
#   ├── VERSION
#   ├── bin\smbanything.exe
#   ├── bin\wintun-amd64.dll
#   └── share\doc\smbanything\WINTUN-LICENSE.txt
#
# Runs on Windows under PowerShell 7 with cargo, the MSVC toolchain and WiX 5 on PATH
# (`dotnet tool install --global wix --version 5.0.2`; the UI extension the wizard pages
# come from is fetched below). packaging/verify-windows-msi.ps1 then installs the result,
# runs it and removes it.
#Requires -Version 7
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw 'wix is not on PATH: dotnet tool install --global wix --version 5.0.2'
}
# The stock dialog set lives in an extension pinned to the same WiX version. Adding it again
# is a no-op, so this needs no state on the machine beyond wix itself.
$uiExt = 'WixToolset.UI.wixext'
& wix extension add -g "$uiExt/5.0.2"
if ($LASTEXITCODE -ne 0) { throw "wix extension add $uiExt failed (exit $LASTEXITCODE)" }

# The version from cargo's own parse of the manifest rather than a regex over it — the same
# `[package]` value the tarball script reads with tomllib, without needing a Python.
$metadata = & cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed (exit $LASTEXITCODE)" }
$version = ($metadata.packages | Where-Object { $_.name -eq 'smbanything' }).version
if ($version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
    throw "invalid version in Cargo.toml: '$version'"
}
# Windows Installer versions are three numbers (major and minor under 256, build under 65536)
# and nothing else, so a pre-release suffix is dropped from the MSI's ProductVersion and kept in
# the VERSION file and `--version`: 0.0.9-rc.1 and 0.0.9 are both ProductVersion 0.0.9. The
# upgrade policy in smbanything.wxs is built around that — an MSI replaces an installed one of
# the same x.y.z (so a prerelease upgrades to its final release in place), and within one x.y.z
# the last one installed wins, since Windows Installer has nothing to order prereleases by.
$msiVersion = $version -replace '[-+].*$', ''
$parts = $msiVersion.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw "$msiVersion does not fit an MSI ProductVersion (255.255.65535)"
}
if ($msiVersion -ne $version) { Write-Host ">> MSI ProductVersion $msiVersion for $version" }

Write-Host '>> building release binary'
& cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
# cargo honours CARGO_TARGET_DIR, and so must this.
$targetDir = ($metadata.target_directory)
$exe = Join-Path $targetDir 'release\smbanything.exe'
if (-not (Test-Path $exe)) { throw "no release binary at $exe" }
$reported = (& $exe --version) -join ' '
if ($LASTEXITCODE -ne 0 -or $reported -ne "smbanything $version") {
    throw "the built binary reports '$reported', not 'smbanything $version'"
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) "smbanything-msi-$PID"
try {
    Write-Host ">> assembling smbanything-$version"
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force -Path "$stage\bin", "$stage\share\doc\smbanything" | Out-Null
    Copy-Item $exe "$stage\bin\smbanything.exe"
    Copy-Item 'vendor\wintun\wintun-amd64.dll' "$stage\bin\wintun-amd64.dll"
    Copy-Item 'vendor\wintun\LICENSE.txt' "$stage\share\doc\smbanything\WINTUN-LICENSE.txt"
    # Bare LF and no BOM, like the tarball's VERSION.
    [System.IO.File]::WriteAllText("$stage\VERSION", "$version`n")

    New-Item -ItemType Directory -Force -Path dist | Out-Null
    # Unversioned, like smbanything-linux-amd64.deb: the version is inside, and the release
    # page's `latest/download` URL stays stable.
    $msi = Join-Path (Resolve-Path dist).Path 'smbanything-windows-x86_64.msi'
    if (Test-Path $msi) { Remove-Item -Force $msi }
    Write-Host '>> building the MSI'
    & wix build -arch x64 -ext $uiExt -d "Version=$msiVersion" -d "Stage=$stage" -o $msi packaging\windows\smbanything.wxs
    if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
    if (-not (Test-Path $msi)) { throw "wix build wrote no $msi" }
    Write-Host ">> wrote dist\smbanything-windows-x86_64.msi ($([math]::Round((Get-Item $msi).Length / 1MB, 1)) MB)"
} finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
