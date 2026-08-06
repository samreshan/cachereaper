<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png" />
    <img src="assets/logo.png" alt="cachereaper" width="400" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/samreshan/cachereaper/releases/latest">
    <img src="assets/download.png" alt="Download cachereaper" width="230" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/samreshan/cachereaper/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/samreshan/cachereaper?style=flat-square&color=ea1d1f&label=latest" /></a>
  <img alt="macOS universal" src="https://img.shields.io/badge/macOS-universal-5a5a5a?style=flat-square" />
  <img alt="Windows x64" src="https://img.shields.io/badge/Windows-x64-5a5a5a?style=flat-square" />
  <img alt="Python 3.9+" src="https://img.shields.io/badge/CLI-Python%203.9%2B-5a5a5a?style=flat-square" />
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-5a5a5a?style=flat-square" /></a>
</p>

Reclaim disk space from caches and build artifacts, with a risk tier on every
finding and guards that make it hard to delete something you wanted.

**Nothing is deleted without a rule**, and every rule carries a tier and a
"here's how you get it back" note. **Build artifacts must prove what they are** —
a `target/` is only a Rust build if `Cargo.toml` sits beside it; ambiguous names
like `dist/` are claimed only when git already ignores them. **Dry-run is the
default.**

```
LOW RISK      pure caches, regenerate automatically   [5.0G]
  --------------------------------------------------------------------------
      1.2G        pnpm-store                 pnpm content store
      1.2G  x17   app-cache                  app HTTP cache
    800.1M        vscode-vsix                VS Code extension installers
    595.3M        cargo-registry             cargo crate sources + archives

MEDIUM RISK   reinstallable, costs you time/bandwidth   [3.2G]
  --------------------------------------------------------------------------
    701.3M        nuget-packages             NuGet global packages
    255.2M  x7    node-modules               installed npm packages

HIGH RISK     stateful or expensive - review each one   [1.8G]
  --------------------------------------------------------------------------
      1.4G        rustup-toolchains          rust toolchains
            ! prefer `rustup toolchain uninstall <old>` to keep the active one
```

## Install

**Desktop app, macOS** — downloads the [latest release](https://github.com/samreshan/cachereaper/releases/latest)
into `/Applications`, ready to open:

```bash
curl -fsSL https://raw.githubusercontent.com/samreshan/cachereaper/main/install.sh -o install.sh
bash install.sh
```

**Desktop app, Windows 10/11** — run
[`cachereaper-windows-x64-setup.exe`](https://github.com/samreshan/cachereaper/releases/latest/download/cachereaper-windows-x64-setup.exe).
There is an [`.msi`](https://github.com/samreshan/cachereaper/releases/latest/download/cachereaper-windows-x64.msi)
for deploying it centrally.

**CLI** — one file, no dependencies, Python 3.9+, macOS, Linux and Windows:

```bash
git clone https://github.com/samreshan/cachereaper
install -m 755 cachereaper/cachereaper.py ~/.local/bin/cachereaper
```

<details>
<summary>Downloaded the <code>.dmg</code> by hand and macOS says it is damaged?</summary>

It isn't. The app is signed ad-hoc rather than with an Apple Developer ID (that
needs a paid membership), so Gatekeeper can't attribute it to anyone and says
"damaged" when it means *unidentified*. On macOS 15+ there is no right-click →
Open for this any more. After dragging it to Applications:

```bash
xattr -dr com.apple.quarantine /Applications/cachereaper.app
```

That clears the flag macOS puts on browser downloads — the same decision the
Privacy & Security pane asks for, made up front. `install.sh` does it for you.
Building from source with `./gui/release.sh` avoids the question entirely.
</details>

<details>
<summary>Windows says "Windows protected your PC"?</summary>

Same cause, different wording. The installer is not signed with a paid code
signing certificate, so SmartScreen has no publisher to name and warns about
what it cannot identify rather than what it found. Choose **More info → Run
anyway**.
</details>

## Use it

```bash
cachereaper                                  # scan, low-risk only (default)
cachereaper scan --tier high -v              # everything, with individual paths
cachereaper select                           # pick what to remove, interactively
cachereaper clean --tier low                 # delete safe caches (confirms first)
cachereaper clean --tier medium --dry-run    # rehearse it
cachereaper tools                            # safer vendor commands + all rules
```

`select` opens a picker where low-risk groups start ticked and medium and high
start empty, so pressing `d` immediately does the conservative thing.

| flag | effect |
| --- | --- |
| `--tier low\|medium\|high` | highest tier to include (default `low`) |
| `--stale-days N` | only things untouched for N days |
| `--min-size 10M` | ignore anything smaller |
| `--only` / `--exclude RULE...` | filter by rule id |
| `--roots DIR...` | where to hunt for project artifacts (default `$HOME`) |
| `--system` | also `/Library/Caches`, `/private/var/folders` (sudo to delete) |
| `--json` | machine-readable output |

`cachereaper update` is the only command that touches the network, and it only
does so when you run it. It reports what the newest release is; `--install`
downloads that version and replaces the file you ran, atomically, leaving the
old one intact if anything goes wrong. A copy installed by pip says so and
points you back at pip instead.

## The desktop app

A treemap with the risk tiers painted on top. GrandPerspective shows you what is
big; cachereaper shows you what is big **and** safe to delete.

It opens by asking what to look at rather than walking your disk uninvited, and
holds the window with a live count while it scans. **Scan folder…** repoints it
later — an external drive, one project, `~/Library`.

macOS gates three folders — Desktop, Documents, Downloads — and left alone it
raises a consent dialog for each one mid-scan, from whichever thread got there
first. cachereaper asks for them up front instead, in one screen, with a switch
each. Aim it at a project directory and it asks for nothing at all. Answers live
in `~/.cachereaper/config.json`, and a folder you allowed can be handed back from
the same screen, which resets macOS to asking again.

**The scan itself never raises a dialog.** A folder you have not allowed is not
read, and the Photos library, Contacts, Calendars and Reminders are never read at
all — each is its own consent prompt and no rule claims anything inside them.
Because the app is signed ad-hoc rather than with a Developer ID, macOS ties
those permissions to the exact build, so **upgrading resets them** and the first
scan after an update asks once more.

| | |
| --- | --- |
| **Scan folder…** | choose a different root and rescan |
| click | drill into a folder |
| backspace / **↑** | go back up |
| **Select** mode (or `s`) | click blocks, or drag a box to take many |
| ⌥click in Select | drill in instead of selecting |
| ⌘click in Explore | select the nearest claimed folder |
| right-click · ⌘R | reveal in Finder |
| esc | clear the selection |

Colour carries one meaning: tiers stay saturated, anything unclaimed drains to
grey so it recedes. Dragging a box across a `node_modules` means *that folder*,
not *those 400 files*.

### Updates

The app asks the release page whether there is a newer build each time it opens,
and says nothing unless there is. When there is, a card at the top of the panel
names the version and offers to install it — one click, and it downloads,
replaces itself and restarts. Nothing about your machine is sent, and nothing is
installed without being asked for: this tool deletes files, so the binary that
does that is not something to swap out quietly.

The bottom of the panel has the version, a **Check for updates** button for
asking on the spot, and a **check on launch** switch if you would rather it
didn't. The switch does not affect the button.

Every release is signed with a key whose public half is compiled into the app,
and a download that does not match it is refused rather than installed — which
also means the update path does not care that the app is unsigned as far as
Gatekeeper is concerned. An update installed this way is never quarantined, so
there is no `xattr` step and no Privacy & Security detour on the way to it —
only the folder permissions, which macOS ties to the build and which the first
scan afterwards asks for again.

Copies of 1.4.0 and earlier have no updater in them and have to be replaced once,
by hand, before they can start doing this themselves.

## Risk tiers

| tier | meaning | examples |
| --- | --- | --- |
| **low** | regenerates itself, costs you nothing | npm/pip/cargo caches, Electron app caches, `__pycache__`, DerivedData |
| **medium** | reinstallable, costs time or bandwidth | `node_modules`, virtualenvs, NuGet/Maven caches, git-ignored `dist/` |
| **high** | stateful or expensive — review each | rustup toolchains, simulator devices, Xcode archives |

## What it detects

~55 known cache locations: npm, yarn, pnpm, bun, pip, uv, poetry, cargo, go,
gradle, maven, NuGet, composer, CocoaPods, SwiftPM, deno, Homebrew, Playwright,
Puppeteer, Prisma, Xcode DerivedData and archives, CoreSimulator, VS Code and
Electron app caches, and `Library/Caches/*`.

Plus project build artifacts, each gated on a marker so a directory is never
claimed on its name alone:

| directory | claimed when |
| --- | --- |
| `target/` | `Cargo.toml` or `pom.xml` is a sibling |
| `node_modules/` | always (unambiguous) |
| `.venv/`, `venv/`, `env/` | contains `pyvenv.cfg` |
| `Pods/` · `vendor/` | `Podfile` · `composer.json` is a sibling |
| `.next/`, `.turbo/`, `.vite/`, `.svelte-kit/`, … | `package.json` is a sibling |
| `.gradle/` · `.dart_tool/` · `_build/` | `build.gradle*` · `pubspec.yaml` · `mix.exs` |
| `__pycache__/`, `.pytest_cache/`, `.tox/`, `.terraform/`, … | by name |
| `build/`, `dist/`, `out/`, `obj/` | **only if git already ignores them** |

## Safety

1. **Confined to `$HOME`** plus roots you pass explicitly. `--system` needs root.
2. **Hard-blocked components**, re-checked before every delete: `.git`, `.ssh`,
   `.gnupg`, `Keychains`, `Mobile Documents`, `*.photoslibrary`, and anything
   under OneDrive / Google Drive / Dropbox / iCloud / Nextcloud.
3. **Never follows symlinks or crosses filesystems.**
4. **Re-validated at delete time** — a path that changed since the scan is
   skipped, not deleted.
5. **Stateful data is not a rule at all**: VM disks, chat history, `Downloads`,
   and source directories are never offered.
6. **Everything is logged** to `~/.cachereaper/reap-<timestamp>.jsonl` with the
   path, rule, bytes, and restore command.
7. **High risk requires typing a phrase**, not just `y`.

Where a vendor command is safer than `rm -rf` — Docker, Colima, rustup, simctl,
Time Machine snapshots — `cachereaper tools` prints the command instead.

## Build and test

The rule table lives in `cachereaper.py` and nowhere else; `dump-rules`
generates the copy the Rust core embeds, and CI fails if it drifts. The guards
exist in both languages, held honest by shared vectors both suites assert
against.

```bash
./gui/dev.sh ~/Programming                        # map in a browser, no desktop build
./gui/release.sh                                  # universal .app + .dmg

python3 -m unittest discover -s tests             # CLI
cargo test --manifest-path gui/core/Cargo.toml    # scanner, guards, deletion
node gui/tests/treemap.test.mjs                   # treemap layout
```

New rules are the most useful contribution. A rule needs an id, a tier, a label,
and an honest `regen` string. If the name is ambiguous, gate it behind a marker
or `need_gitignored=True` rather than claiming it outright.

## License

MIT
