# Install the MSI packaging/build-windows-msi.ps1 wrote, prove the installed program runs from
# where the package put it with the Wintun driver it needs beside it, remove the package, and
# prove nothing of it is left. This is the smoke test the release workflow's Windows row and
# ci/windows/ci.ps1 run; it needs an elevated PowerShell 7 (msiexec /qn installs per machine).
#Requires -Version 7
param([string] $Msi = 'dist\smbanything-windows-x86_64.msi')
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msi = (Resolve-Path $Msi).Path
$root = Join-Path $env:ProgramFiles 'smbanything'
$binDir = Join-Path $root 'bin'
$exe = Join-Path $binDir 'smbanything.exe'

function Invoke-Msiexec([string[]] $Arguments, [string] $What) {
    $log = Join-Path $env:TEMP "smbanything-msi-$What.log"
    $p = Start-Process msiexec -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', $log)) -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $log | Select-Object -Last 40
        throw "msiexec $What exited $($p.ExitCode)"
    }
}
function Test-OnMachinePath([string] $Dir) {
    $entries = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
    [bool]($entries | Where-Object { $_.TrimEnd('\') -ieq $Dir })
}

if (Test-Path $root) { throw "$root exists before the install — remove the previous smbanything first" }

# The install below is silent, so the wizard is checked in the package itself: an MSI with no
# UI shows a progress bar and closes, and the finish page is what tells the operator it
# worked. The tables are read through Windows Installer's own COM object.
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($Msi, 0)
function Read-MsiRows([string] $Sql, [string[]] $Columns) {
    # COM methods echo their (void) results into the pipeline; only the rows may come out.
    $view = $db.OpenView($Sql)
    $null = $view.Execute()
    while ($true) {
        $record = $view.Fetch()
        if ($null -eq $record) { break }
        $row = [ordered]@{}
        for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = $record.StringData($i + 1) }
        [pscustomobject]$row
    }
    $null = $view.Close()
}
$dialogs = @(Read-MsiRows "SELECT ``Dialog`` FROM ``Dialog``" @('Dialog') | ForEach-Object Dialog)
foreach ($dialog in 'WelcomeDlg', 'InstallDirDlg', 'VerifyReadyDlg', 'ProgressDlg', 'ExitDialog') {
    if ($dialogs -notcontains $dialog) { throw "the package has no $dialog page (dialogs: $($dialogs -join ', '))" }
}
# The licence page stays in the table — the dialog set defines it — but the welcome page's Next
# must lead past it: of the NewDialog events on that button the highest-ordered one fires last
# and wins, and it has to be the one smbanything.wxs adds.
$next = Read-MsiRows "SELECT ``Argument``, ``Ordering`` FROM ``ControlEvent`` WHERE ``Dialog_``='WelcomeDlg' AND ``Control_``='Next' AND ``Event``='NewDialog'" @('Argument', 'Ordering') |
    Sort-Object { [int]$_.Ordering } | Select-Object -Last 1
if ($next.Argument -ne 'InstallDirDlg') { throw "the welcome page's Next leads to '$($next.Argument)', not the folder page" }
Write-Host "   the wizard has its $($dialogs.Count) pages, finish page included, and skips the licence page"

Write-Host ">> installing $Msi"
Invoke-Msiexec @('/i', $Msi) 'install'
foreach ($file in 'bin\smbanything.exe', 'bin\wintun-amd64.dll', 'VERSION', 'share\doc\smbanything\WINTUN-LICENSE.txt') {
    if (-not (Test-Path (Join-Path $root $file))) { throw "the installed tree lacks $file" }
}
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
$reported = (& $exe --version) -join ' '
if ($LASTEXITCODE -ne 0) { throw "smbanything.exe --version exited $LASTEXITCODE" }
if ($reported -ne "smbanything $version") { throw "--version says '$reported', VERSION says $version" }
Write-Host "   $reported"
# --smb-tun refuses any DLL but the pinned one, so the installed copy must be the vendored file.
$installedDll = (Get-FileHash -Algorithm SHA256 (Join-Path $binDir 'wintun-amd64.dll')).Hash
$vendoredDll = (Get-FileHash -Algorithm SHA256 'vendor\wintun\wintun-amd64.dll').Hash
if ($installedDll -ne $vendoredDll) { throw "the installed wintun-amd64.dll ($installedDll) is not the vendored one ($vendoredDll)" }
Write-Host '   wintun-amd64.dll sits beside smbanything.exe and matches the vendored driver'
if (-not (Test-OnMachinePath $binDir)) { throw "the machine PATH lacks $binDir" }
Write-Host "   $binDir is on the machine PATH"

Write-Host '>> removing it'
Invoke-Msiexec @('/x', $Msi) 'uninstall'
if (Test-Path $root) { throw "$root survived the uninstall" }
if (Test-OnMachinePath $binDir) { throw "the machine PATH still names $binDir" }
Write-Host '   removed cleanly'
