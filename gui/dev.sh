#!/usr/bin/env bash
# Run the treemap in a browser, without the Tauri shell.
#
#   gui/dev.sh              # scan $HOME
#   gui/dev.sh ~/Programming
#   gui/dev.sh ~/Programming 8899
#
# Scans with the Rust core, writes gui/dist/snapshot.json, serves gui/dist on
# localhost and opens it. Ctrl-C stops the server.

set -euo pipefail

ROOT="${1:-$HOME}"
PORT="${2:-8777}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found — install Rust from https://rustup.rs" >&2
  exit 1
fi

echo "building scanner…"
cargo build --release --quiet --manifest-path "$HERE/core/Cargo.toml"

echo "scanning ${ROOT} …"
"$HERE/core/target/release/snapshot" tree "$ROOT" "$HERE/dist/snapshot.json"

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is already in use — pass a different one: gui/dev.sh '$ROOT' 8899" >&2
  exit 1
fi

echo
echo "  http://127.0.0.1:${PORT}/     (Ctrl-C to stop)"
echo
echo "  click        drill in            backspace / ↑ up   go up"
echo "  cmd-click    select a finding    esc                clear selection"
echo

cd "$HERE/dist"
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true' EXIT INT TERM

sleep 1
if command -v open >/dev/null 2>&1; then
  open "http://127.0.0.1:${PORT}/"
fi

wait "$SERVER"
