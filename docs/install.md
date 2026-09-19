# Installing smbanything

Install a native package from the
[latest release](https://github.com/andrewtheguy/smbanything/releases/latest).
The package manager owns the one executable (plus, on Windows, the Wintun
driver beside it). smbanything keeps no config and no state, so upgrading or
removing the package leaves nothing behind.

## Debian and Ubuntu (`.deb`)

Releases provide `smbanything-linux-amd64.deb` and `smbanything-linux-arm64.deb`:

```sh
curl -fsSLO https://github.com/andrewtheguy/smbanything/releases/latest/download/smbanything-linux-amd64.deb
sudo apt install ./smbanything-linux-amd64.deb
```

Use the `arm64` filename on an arm64 host. The package installs
`/usr/bin/smbanything` and needs glibc 2.39 or newer (Debian 13, Ubuntu 24.04).
It suggests `cifs-utils`, which provides the `mount -t cifs` the Linux mount
command uses.

## Fedora, RHEL, and other RPM distributions (`.rpm`)

Releases provide `smbanything-linux-amd64.rpm` and `smbanything-linux-arm64.rpm`:

```sh
curl -fsSLO https://github.com/andrewtheguy/smbanything/releases/latest/download/smbanything-linux-amd64.rpm
sudo dnf install ./smbanything-linux-amd64.rpm
```

Use the `arm64` filename on an arm64 host. The package installs
`/usr/bin/smbanything`, like the `.deb`.

## macOS (`.pkg`)

The package is arm64:

```sh
curl -fsSLO https://github.com/andrewtheguy/smbanything/releases/latest/download/smbanything-macos-arm64.pkg
sudo installer -pkg smbanything-macos-arm64.pkg -target /
```

It installs `/usr/local/bin/smbanything`. The package is unsigned and not
notarized. A browser download is quarantined, so fetch it with `curl` as shown
and install it from the terminal.

## Windows (`.msi`)

Windows x86-64, from PowerShell 7 (`pwsh`):

```powershell
Invoke-WebRequest https://github.com/andrewtheguy/smbanything/releases/latest/download/smbanything-windows-x86_64.msi -OutFile smbanything-windows-x86_64.msi
msiexec /i smbanything-windows-x86_64.msi
```

The package is unsigned, so SmartScreen asks before it runs. It opens the usual
install wizard — folder, confirm, and a finish page — and puts `bin` on the
machine `PATH`, so `smbanything` works in a shell opened after the install:

```text
C:\Program Files\smbanything\bin\smbanything.exe
C:\Program Files\smbanything\bin\wintun-amd64.dll
C:\Program Files\smbanything\share\doc\smbanything\WINTUN-LICENSE.txt
```

`wintun-amd64.dll` is the pinned Wintun driver `--smb-tun` loads from beside
the executable; see [smb-tun.md](smb-tun.md). Add `/qn` for an unattended
install.

## Other Linux and macOS hosts

The release also carries `smbanything-<version>-<os>-<arch>.tar.gz`, the payload
the packages are built from: `bin/smbanything` and a `VERSION` file. Put the
binary anywhere on `PATH`.

## Upgrade

Download the new asset and hand it to the same package manager:

```sh
sudo apt install ./smbanything-linux-amd64.deb
sudo dnf upgrade ./smbanything-linux-amd64.rpm
sudo installer -pkg smbanything-macos-arm64.pkg -target /
msiexec /i smbanything-windows-x86_64.msi
```

Use only the command for the host platform. Files are replaced in place.

Windows Installer versions have no prerelease part, so the MSI of `x.y.z-rc.1`
and of `x.y.z` carry the same version: either replaces the other in place, and
within one `x.y.z` the one installed last wins. A lower `x.y.z` is refused as a
downgrade.

## Uninstall

On Debian or Ubuntu:

```sh
sudo apt remove smbanything
```

On an RPM distribution:

```sh
sudo dnf remove smbanything
```

On macOS there is no package manager to ask, so the repository ships an
uninstaller that reads the installed receipt and removes exactly what the
package wrote:

```sh
curl -fsSLO https://raw.githubusercontent.com/andrewtheguy/smbanything/main/packaging/uninstall-macos-pkg.sh
sudo bash uninstall-macos-pkg.sh
```

`--dry-run` prints the removals without making them and needs no `sudo`. By
hand it is:

```sh
sudo rm -f /usr/local/bin/smbanything
sudo pkgutil --forget com.andrewtheguy.smbanything
```

On Windows, remove smbanything from **Apps & features**.

## Build release packages

See [`packaging/README.md`](../packaging/README.md).
