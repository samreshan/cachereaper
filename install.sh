#!/usr/bin/env bash
# Install the cachereaper desktop app into /Applications.
#
#   ./install.sh                 # latest release
#   ./install.sh v1.1.1          # a specific tag
#   DEST=~/Applications ./install.sh
#
# Why this exists.
#
# The app is signed ad-hoc, not with an Apple Developer ID, because a Developer
# ID needs a paid Apple Developer Program membership. macOS attaches a quarantine
# flag to anything a browser downloads, and Gatekeeper refuses to launch a
# quarantined app that has no Developer ID. Until macOS 14 you could get past
# that by right-clicking the app and choosing Open. macOS 15 removed that path:
# the only click-through left is System Settings > Privacy & Security > Open
# Anyway, after a failed launch.
#
# So this script downloads with curl and clears the quarantine flag before the
# app is ever launched, which is the same decision you would be making in that
# settings pane, made once and up front.
#
# It is doing exactly one privileged thing, on one path, and you can read it.
# If you would rather not run it: drag the app out of the .dmg yourself and run
#   xattr -dr com.apple.quarantine /Applications/cachereaper.app
# or build from source with ./gui/release.sh, which is never quarantined.

set -euo pipefail

REPO="samreshan/cachereaper"
TAG="${1:-latest}"
DEST="${DEST:-/Applications}"
APP="cachereaper.app"

[ "$(uname -s)" = "Darwin" ] || { echo "macOS only — the CLI works everywhere: see the README" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }

if [ "$TAG" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download"
  # The filename carries the version, so read it back out of the redirect
  # rather than guessing.
  VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/v||')
else
  URL="https://github.com/$REPO/releases/download/$TAG"
  VERSION="${TAG#v}"
fi
DMG="cachereaper_${VERSION}_universal.dmg"

TMP="$(mktemp -d)"
MNT="$TMP/mnt"
cleanup() {
  [ -d "$MNT" ] && hdiutil detach "$MNT" -quiet 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "downloading $DMG"
curl -fL --progress-bar -o "$TMP/$DMG" "$URL/$DMG"

echo "mounting"
mkdir -p "$MNT"
hdiutil attach "$TMP/$DMG" -nobrowse -quiet -mountpoint "$MNT"
[ -d "$MNT/$APP" ] || { echo "no $APP inside the disk image" >&2; exit 1; }

if [ -e "$DEST/$APP" ]; then
  echo "replacing the copy already in $DEST"
  rm -rf "$DEST/$APP"
fi

echo "copying to $DEST"
cp -R "$MNT/$APP" "$DEST/$APP"

# The point of the whole script.
xattr -dr com.apple.quarantine "$DEST/$APP" 2>/dev/null || true

echo
echo "  installed $DEST/$APP ($VERSION)"
echo "  open it from Launchpad, or: open '$DEST/$APP'"
