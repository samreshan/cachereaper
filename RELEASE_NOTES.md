# CacheReaper 2.1.0 — Rules that prove it

Some space cannot be judged by where it sits. An old VS Code extension looks
exactly like the current one, and a Codex worktree is safe to remove only while
git says nothing in it would be lost. CacheReaper 2.1 adds rules for places like
these. Each one claims a folder only when it can prove the folder is disposable,
and proves it again immediately before deleting it.

## New rules

- **Superseded editor extensions** (low risk): VS Code, VS Code Insiders and
  Cursor record replaced versions in `extensions/.obsolete`. A folder is claimed
  only when it is listed there and missing from `extensions.json`. Version
  numbers are never compared.
- **Claude Code session temp folders** (medium, macOS): a session folder in your
  own `/tmp/claude-<uid>` that nothing has written to for 7 days.
- **brag video intermediates** (medium): the `work/` folder of a `brag-output*`
  folder, once `brag-plan.md` and a finished `.mp4` sit beside it. The finished
  video is never claimed.
- **Finished Codex worktrees** (high): a linked worktree in `~/.codex/worktrees`
  with a clean `git status` and every commit on a remote. It is removed with
  `git worktree remove`, so the main repository forgets it too.
- **Adobe leftovers** (medium, CLI with `--system`): an `Adobe <product>
  <version>` support folder whose version is no longer installed, when a sibling
  folder for an installed version shows how that product names its folders.
- **Simulator dyld caches** (low, CLI with `--system`) and **Google Updater
  downloads** (low).

## Desktop app

The desktop app now shows and deletes these rules too, using the same proofs. A
finding appears only when the scanned folder contains it. Adobe leftovers and
simulator dyld caches are system locations the app cannot delete, so it does not
show them; use `sudo cachereaper clean --system` instead.

## Safety

- Every proof runs again immediately before deletion. A folder that changed
  after the scan, such as a reinstalled extension, a resumed session or an
  edited worktree, is skipped as "no longer proven".
- Deletion stays confined to your home folder and the folders you scanned, plus
  your own `/tmp/claude-<uid>` for Claude Code session folders. Every level of
  that path must be a real directory you own.
- OneDrive's Lists cache stays behind the cloud-sync guard, and simulator
  runtimes can only be removed by `xcrun simctl runtime delete`.
  `cachereaper tools` prints the commands for both.

## Upgrading

Existing desktop installations from 1.5 or later should offer 2.1.0 through the
built-in updater. Earlier desktop versions should install the latest package
manually. The Python CLI can update itself with `cachereaper update --install`.

## Verification

The release candidate passed 152 Rust core tests on macOS, Linux and Windows,
79 Python CLI tests, 133 frontend checks, strict Clippy and an optimized desktop
build. On a real Mac, the desktop app's finders returned the same 21 paths as
the CLI.
