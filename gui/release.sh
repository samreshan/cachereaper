#!/usr/bin/env bash
# Package the desktop app for distribution: universal .app + .dmg.
#
#   gui/release.sh
#
# Tauri embeds everything under gui/dist into the executable. dev.sh writes a
# scanned snapshot.json into that same directory, so building straight after a
# dev run ships a listing of whoever's home directory was scanned last, inside
# the .dmg, to everyone who downloads it. That file is removed here rather than
# in .gitignore, because gitignore does not stop the bundler from reading it.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$HERE/src-tauri/tauri.conf.json"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found — install Rust from https://rustup.rs" >&2
  exit 1
fi
if ! cargo tauri --version >/dev/null 2>&1; then
  echo "tauri-cli not found — cargo install tauri-cli --version '^2'" >&2
  exit 1
fi

if [ -f "$HERE/dist/snapshot.json" ]; then
  echo "removing the dev snapshot so it is not bundled"
  rm -f "$HERE/dist/snapshot.json"
fi

for target in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target list --installed 2>/dev/null | grep -qx "$target" || {
    echo "missing rust target $target — rustup target add $target" >&2
    exit 1
  }
done

OUT="$HERE/src-tauri/target/universal-apple-darwin/release/bundle"

# bundle_dmg.sh builds a read-write image, mounts it, arranges the window and
# converts it. A run that dies anywhere in the middle — or is interrupted —
# leaves the volume mounted and the scratch image behind, and every build after
# that fails on the leftovers rather than on anything wrong with the build. It
# does not clean up after itself, so do it here before starting.
for volume in $(hdiutil info | grep -o '/Volumes/dmg\.[A-Za-z0-9]*' | sort -u); do
  echo "detaching a leftover build volume: $volume"
  hdiutil detach "$volume" -force -quiet 2>/dev/null || true
done
rm -f "$OUT"/macos/rw.*.dmg "$OUT"/dmg/*.dmg

cargo tauri build --target universal-apple-darwin --config "$CONF"
echo
echo "  app: $OUT/macos/cachereaper.app"
echo "  dmg: $(ls "$OUT"/dmg/*.dmg 2>/dev/null | head -1)"
echo
echo "  Ad-hoc signed, not notarised. macOS 15+ has no right-click -> Open for"
echo "  this any more, so clear the quarantine flag after copying it somewhere:"
echo "      xattr -dr com.apple.quarantine /Applications/cachereaper.app"
echo "  install.sh in the repo root does that as part of installing."
