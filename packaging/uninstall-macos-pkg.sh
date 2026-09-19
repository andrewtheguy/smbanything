#!/usr/bin/env bash
# Remove the macOS package installed with
# `installer -pkg smbanything-macos-arm64.pkg -target /`.
#
# The removal is driven by the installed receipt, not by a hardcoded file list:
# `pkgutil --files` names exactly what this package put on disk, so an older
# receipt removes that version's files. Directories are left alone — the
# package owns none of its own, only the shared /usr/local prefixes pkgbuild
# also records.
#
#   --dry-run   print what would be removed, change nothing
#
# Run with sudo; the payload lives under a root-owned prefix.
set -euo pipefail

pkgid=com.andrewtheguy.smbanything
dry_run=false

case "${1:-}" in
  --dry-run) dry_run=true ;;
  "") : ;;
  *) echo "usage: $(basename "$0") [--dry-run]" >&2; exit 2 ;;
esac

[ "$(uname -s)" = Darwin ] || { echo "error: this uninstaller is macOS-only" >&2; exit 1; }

if ! info="$(pkgutil --pkg-info "$pkgid" 2>/dev/null)"; then
  echo "error: no receipt for $pkgid — the package is not installed" >&2
  exit 1
fi

if [ "$dry_run" = false ] && [ "$(id -u)" -ne 0 ]; then
  echo "error: run with sudo" >&2
  exit 1
fi

# Where the receipt says the payload was written. Read both fields rather than
# assume: `installer -target /` records a volume of / and leaves the location
# empty, while other receipts spell that same root as `/`. Both forms collapse
# to an empty root here, which is what makes the payload paths absolute.
volume="$(printf '%s\n' "$info" | awk -F': ' '/^volume: /{print $2}')"
location="$(printf '%s\n' "$info" | awk -F': ' '/^location: /{print $2}')"
root="${volume%/}/${location#/}"
root="${root%/}"

# A receipt is only as trustworthy as whatever wrote it, and this script
# deletes: nothing outside the prefix the package is built for is touched.
under_prefix() {
  case "$1" in
    usr/local/?*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    */../*|*/..|../*) return 1 ;;
  esac
  return 0
}

removed=0
while IFS= read -r relative; do
  [ -n "$relative" ] || continue
  # pkgbuild records each payload path's extended attributes (a session macOS
  # tags with com.apple.provenance, say) as an AppleDouble `._*` sibling. The
  # installer folds those back into attributes and never writes them as files,
  # so they are receipt entries with nothing on disk.
  case "${relative##*/}" in ._*) continue ;; esac
  under_prefix "$relative" || {
    echo "error: receipt names a file outside /usr/local: $relative" >&2
    exit 1
  }
  path="$root/$relative"
  if [ -e "$path" ] || [ -L "$path" ]; then
    if [ "$dry_run" = true ]; then
      echo "would: rm $path"
    else
      rm -f "$path"
      echo ">> removed $path"
    fi
    removed=$((removed + 1))
  fi
done < <(pkgutil --only-files --files "$pkgid")

if [ "$dry_run" = true ]; then
  echo "would: pkgutil --forget $pkgid"
  echo ">> $removed payload file(s) would be removed"
else
  pkgutil --forget "$pkgid"
  echo ">> $removed payload file(s) removed"
fi
