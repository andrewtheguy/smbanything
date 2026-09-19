# Packaging

Native packages are the release install contract. Linux ships both `.deb` and
`.rpm`, macOS ships `.pkg`, and Windows ships `.msi`. The distro-agnostic
tarball is the layout input for the Unix packages and a fallback for hosts no
package fits. Installing them is covered in [docs/install.md](../docs/install.md).

## Layouts

```text
Linux:   /usr/bin/smbanything
macOS:   /usr/local/bin/smbanything
Windows: C:\Program Files\smbanything\bin\smbanything.exe
         C:\Program Files\smbanything\bin\wintun-amd64.dll
         C:\Program Files\smbanything\share\doc\smbanything\WINTUN-LICENSE.txt
         C:\Program Files\smbanything\VERSION
```

The MSI puts its `bin` on the machine `PATH`. Wintun has to sit beside the
executable because that is the only place `--smb-tun` loads it from, after
checking its pinned SHA-256; its licence travels with it as its
redistribution terms require. There is no package wrapper, version directory,
service, or config: smbanything keeps no state between runs.

## Scripts

| Path | Purpose |
|---|---|
| `build-tarball.sh` | build the binary and assemble the common release payload |
| `build-native-packages.sh` | consume that payload and build `.deb` + `.rpm` or `.pkg` |
| `build-windows-msi.ps1` | build the binary on Windows and the `.msi` from `windows/smbanything.wxs` (WiX 5) |
| `verify-windows-msi.ps1` | install that `.msi`, run the installed binary, remove it, check nothing is left |
| `uninstall-macos-pkg.sh` | remove the installed `.pkg` by its receipt and forget it |

## Local build

```sh
bash packaging/build-tarball.sh
bash packaging/build-native-packages.sh
```

The native builder needs Python 3.11+ (for `tomllib`), plus `dpkg-deb` and
`rpmbuild` on Linux, or `pkgbuild` on macOS. On Windows, in PowerShell 7 with
WiX on `PATH` (`dotnet tool install --global wix --version 5.0.2`):

```powershell
pwsh -File packaging\build-windows-msi.ps1
pwsh -File packaging\verify-windows-msi.ps1   # elevated: installs and removes it
```

`ci/windows/ci.ps1` runs both after its smoke test. Outputs are:

```text
dist/smbanything-<version>-linux-x86_64.tar.gz
dist/smbanything-linux-amd64.deb
dist/smbanything-linux-amd64.rpm
dist/smbanything-macos-arm64.pkg
dist/smbanything-windows-x86_64.msi
```

Arm Linux uses `arm64` in the asset names. The package filenames are
unversioned so the release page's `latest/download` URLs stay stable.

A `.pkg` built from a session macOS tags with `com.apple.provenance` (a
GUI-launched shell, for one) records each path's extended attributes as `._*`
AppleDouble entries in its receipt. The installer turns them back into
attributes rather than files, and `uninstall-macos-pkg.sh` skips them.

## Releases

`.github/workflows/release.yml` creates a draft, builds the tarballs and native
packages on Linux x86-64 (pinned to Ubuntu 24.04, whose glibc is the `.deb`'s
floor), Linux arm64, and macOS arm64, and builds, installs and removes the MSI
on Windows x86-64. The release is published only after every package succeeds.
