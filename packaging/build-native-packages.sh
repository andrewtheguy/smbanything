#!/usr/bin/env bash
# Build the native installer(s) for the current platform from the release
# tarball produced by build-tarball.sh.
#
# Linux produces both package formats from the same payload:
#   dist/smbanything-linux-amd64.deb
#   dist/smbanything-linux-amd64.rpm
#
# macOS produces:
#   dist/smbanything-macos-arm64.pkg
#
# Native packages use package-manager-owned paths directly. There is no
# versioned tree, active-version symlink, rollback copy, or package wrapper:
#
#   Linux: /usr/bin/smbanything
#   macOS: /usr/local/bin/smbanything
#
# smbanything keeps no config and no state, so the binary is the whole package.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$(python3 -c '
import re, sys, tomllib
with open("Cargo.toml", "rb") as f:
    version = tomllib.load(f)["package"]["version"]
if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
    sys.exit(f"invalid version in Cargo.toml: {version!r}")
print(version)
')"

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)
    tar_arch=x86_64
    asset_arch=amd64
    ;;
  arm64|aarch64)
    tar_arch=arm64
    asset_arch=arm64
    ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

tarball="dist/smbanything-${version}-${os}-${tar_arch}.tar.gz"
[ -f "$tarball" ] || {
  echo "missing $tarball; run packaging/build-tarball.sh first" >&2
  exit 1
}

mkdir -p tmp dist
stage="$(mktemp -d "$repo_root/tmp/native-packages.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/release"
tar -xzf "$tarball" -C "$stage/release" --strip-components=1
release="$stage/release"

[ -x "$release/bin/smbanything" ] || { echo "release tarball has no executable" >&2; exit 1; }
[ "$(cat "$release/VERSION")" = "$version" ] || { echo "release tarball VERSION does not match Cargo.toml" >&2; exit 1; }

reported="$("$release/bin/smbanything" --version)"
[ "$reported" = "smbanything $version" ] || {
  echo "release binary reports '$reported', expected 'smbanything $version'" >&2
  exit 1
}

if [ "$os" = macos ]; then
  command -v pkgbuild >/dev/null 2>&1 || { echo "pkgbuild is required" >&2; exit 1; }
  payload="$stage/payload"
  mkdir -p "$payload/usr/local/bin"
  cp "$release/bin/smbanything" "$payload/usr/local/bin/smbanything"
  output="dist/smbanything-macos-${asset_arch}.pkg"
  pkgbuild \
    --root "$payload" \
    --identifier com.andrewtheguy.smbanything \
    --version "$version" \
    --install-location / \
    "$output"

  pkgutil --payload-files "$output" > "$stage/pkg-contents"
  grep -qx './usr/local/bin/smbanything' "$stage/pkg-contents"
  echo ">> wrote $output"
  exit 0
fi

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild is required" >&2; exit 1; }

payload="$stage/payload"
mkdir -p "$payload/usr/bin"
cp "$release/bin/smbanything" "$payload/usr/bin/smbanything"

# '-' separates the Debian revision, so a SemVer prerelease has to become '~',
# which sorts before everything: '0.0.1-rc.1-1' would otherwise sort *after* the
# '0.0.1-1' release. '+' is left alone — it is legal in a Debian version and
# already sorts after the plain release, which is what build metadata means.
# `tr`, not '${version//-/~}': bash 5.2 tilde-expands a replacement that begins
# with '~'.
deb_version=$(printf '%s' "$version" | tr -- '-' '~')

deb_root="$stage/deb-root"
cp -R "$payload" "$deb_root"
mkdir -p "$deb_root/DEBIAN"
{
  echo "Package: smbanything"
  echo "Version: ${deb_version}-1"
  echo "Architecture: $asset_arch"
  echo "Maintainer: andrewtheguy <andrewchen5678@gmail.com>"
  echo "Section: net"
  echo "Priority: optional"
  # The release runner is pinned to Ubuntu 24.04, whose glibc sets the floor.
  echo "Depends: libc6 (>= 2.39)"
  # The mount commands the TUI prints use mount.cifs on Linux.
  echo "Suggests: cifs-utils"
  echo "Homepage: https://github.com/andrewtheguy/smbanything"
  echo "Description: Browse ZIP and TAR archives through a read-only SMB share"
  echo " Serves one archive at a time over an authenticated, read-only SMB 2.1"
  echo " share, loaded and unloaded from a terminal UI without remounting."
} > "$deb_root/DEBIAN/control"

deb_output="dist/smbanything-linux-${asset_arch}.deb"
dpkg-deb --build --root-owner-group "$deb_root" "$deb_output"
[ "$(dpkg-deb --field "$deb_output" Package)" = smbanything ]
dpkg-deb --contents "$deb_output" > "$stage/deb-contents"
grep -q '\./usr/bin/smbanything$' "$stage/deb-contents"
echo ">> wrote $deb_output"

# RPM does not accept SemVer's '-' in Version or '+' in either Version or
# Release. Preserve their ordering semantics with '~' for a prerelease and '.'
# for build metadata. Release filenames retain the exact Cargo version through
# the release tag; this only affects RPM's internal version field.
rpm_version=$(printf '%s' "$version" | tr -- '-+' '~.')

rpm_top="$stage/rpmbuild"
mkdir -p "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
spec="$rpm_top/SPECS/smbanything.spec"
{
  echo '%global debug_package %{nil}'
  echo '%global __os_install_post %{nil}'
  echo 'Name: smbanything'
  echo "Version: $rpm_version"
  echo 'Release: 1'
  echo 'Summary: Browse ZIP and TAR archives through a read-only SMB share'
  echo 'License: LicenseRef-smbanything'
  echo 'URL: https://github.com/andrewtheguy/smbanything'
  echo 'Suggests: cifs-utils'
  echo
  echo '%description'
  echo 'Serves one archive at a time over an authenticated, read-only SMB 2.1'
  echo 'share, loaded and unloaded from a terminal UI without remounting.'
  echo
  echo '%prep'
  echo
  echo '%build'
  echo
  echo '%install'
  echo 'mkdir -p %{buildroot}'
  echo 'cp -a "%{payload}/." "%{buildroot}/"'
  echo
  echo '%files'
  echo '/usr/bin/smbanything'
} > "$spec"

rpmbuild -bb \
  --define "_topdir $rpm_top" \
  --define "payload $payload" \
  "$spec"

rpm_built="$(find "$rpm_top/RPMS" -type f -name '*.rpm' -print -quit)"
[ -n "$rpm_built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }
rpm_output="dist/smbanything-linux-${asset_arch}.rpm"
cp "$rpm_built" "$rpm_output"
rpm -qpl "$rpm_output" > "$stage/rpm-contents"
grep -qx '/usr/bin/smbanything' "$stage/rpm-contents"
echo ">> wrote $rpm_output"
