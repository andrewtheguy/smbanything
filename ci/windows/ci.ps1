# Clippy, tests, and a release build, then an SMB smoke test of that binary
# serving the candle 0.11.0 tar.gz fixture from .\tmp — fetched from the
# GitHub release (https://github.com/huggingface/candle/releases/tag/0.11.0)
# when missing — and reading a known file back through the 169.254.255.1
# packet tunnel. The TAR.GZ backing must spill nothing into the runtime temp
# directory while serving or after shutdown. Wintun is the Windows-only
# driver sidecar; Linux and macOS use their native TUN interfaces.
#
# Runs natively on whatever Windows machine invokes it: the CI VM (see
# ci\windows\remote.ps1) or a dev box. Every cargo step checks $LASTEXITCODE
# by hand — a non-zero exit from a native command is not an error to
# PowerShell on its own.
$ErrorActionPreference = 'Stop'

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in.
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    Write-Host ''
    Write-Host "== $Name =="
    Write-Host "   cargo $($Arguments -join ' ')"

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Write-Host '== toolchain =='
& rustc --version
& cargo --version
& cargo clippy --version
if ($env:CARGO_TARGET_DIR) { Write-Host "   CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR" }

Invoke-Step 'Clippy' @('clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')
Invoke-Step 'Test' @('test', '--workspace', '--all-features')
Invoke-Step 'Release build' @('build', '--release')

Write-Host ''
Write-Host '== SMB smoke =='

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'the packet-tunnel smoke must run from an elevated Windows session'
}

$expectedHash = '11ad61a87d8defac2031c6d6d5f88a4d5538df501b88503fddab6f739391169e'
$archive = Join-Path (Get-Location) 'tmp\candle-0.11.0.tar.gz'
if (-not (Test-Path $archive)) {
    Write-Host '[smoke] fetching candle-0.11.0.tar.gz'
    New-Item -ItemType Directory -Force -Path (Split-Path $archive) | Out-Null
    Invoke-WebRequest -Uri 'https://github.com/huggingface/candle/archive/refs/tags/0.11.0.tar.gz' -OutFile $archive
}

$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
$binary = Join-Path $targetDir 'release\smbanything.exe'
$wintun = Join-Path (Get-Location) 'vendor\wintun\wintun-amd64.dll'
Copy-Item -Force $wintun (Join-Path (Split-Path $binary) 'wintun-amd64.dll')
$work = Join-Path (Get-Location) 'tmp\smoke-work'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
$runtimeTmp = Join-Path $work 'runtime-tmp'
New-Item -ItemType Directory -Force -Path $runtimeTmp | Out-Null
$stdout = Join-Path $work 'server.log'
$stderr = Join-Path $work 'server.err.log'
$env:TEMP = $runtimeTmp
$env:TMP = $runtimeTmp
$env:SMBANYTHING_PASSWORD = 'ci-smoke-password'

$server = $null
$drive = $null
try {
    $server = Start-Process -FilePath $binary `
        -ArgumentList @($archive, '--smb-tun') `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    $port = $null
    $folder = $null
    foreach ($attempt in 1..200) {
        if (Test-Path $stdout) {
            $serverText = Get-Content -Raw $stdout
            if ($serverText -match 'Port:\s+(\d+)') { $port = [int] $Matches[1] }
            if ($serverText -match 'Folder:\s+\\\\[^\\]+\\anything\\([0-9a-f]{8})') { $folder = $Matches[1] }
        }
        if ($port -and $folder) { break }
        if ($server.HasExited) {
            throw "smbanything exited early:`n$(Get-Content -Raw $stdout)`n$(Get-Content -Raw $stderr)"
        }
        Start-Sleep -Milliseconds 50
        $server.Refresh()
    }
    if (-not $port -or -not $folder) {
        throw "timed out waiting for smbanything:`n$(Get-Content -Raw $stdout)"
    }

    if (Get-ChildItem -Force $runtimeTmp | Select-Object -First 1) {
        throw 'the TAR.GZ backing created temporary files while serving'
    }

    $drive = @('Z', 'Y', 'X', 'W', 'V', 'U') |
        Where-Object { -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
        Select-Object -First 1
    if (-not $drive) { throw 'no unused drive letter is available for the SMB smoke' }

    if ($port -ne 445) { throw "packet tunnel reported port $port instead of 445" }
    $unc = "\\169.254.255.1\anything\$folder"
    $mapOutput = & net.exe use "${drive}:" $unc 'ci-smoke-password' /user:smbanything 2>&1
    $mapCode = $LASTEXITCODE
    $mapOutput | ForEach-Object { Write-Host "$_" }
    if ($mapCode -ne 0) { throw "net use failed with exit code $mapCode" }

    $servedFile = "${drive}:\candle-0.11.0\Cargo.toml"
    $actualHash = (Get-FileHash -Algorithm SHA256 $servedFile).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw "served file hash mismatch: $actualHash" }
    Write-Host "[smoke] verified candle-0.11.0.tar.gz through 169.254.255.1 ($actualHash)"
}
finally {
    if ($drive) {
        & net.exe use "${drive}:" /delete /y 2>&1 | ForEach-Object { Write-Host "$_" }
    }
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        Wait-Process -Id $server.Id -ErrorAction SilentlyContinue
    }
}

foreach ($attempt in 1..100) {
    $adapter = Get-NetAdapter -Name 'smbanything' -ErrorAction SilentlyContinue
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -like '169.254.255.*' }
    if (-not $adapter -and -not $routes) { break }
    Start-Sleep -Milliseconds 50
}
if ($adapter -or $routes) {
    throw 'the packet tunnel left its adapter or 169.254.255.* routes behind'
}

if (Get-ChildItem -Force $runtimeTmp | Select-Object -First 1) {
    throw 'the TAR.GZ backing left temporary files after server shutdown'
}

Write-Host ''
Write-Host 'all steps passed'
exit 0
