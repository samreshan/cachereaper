<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png" />
    <img src="assets/logo.png" alt="cachereaper" width="440" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/samreshan/cachereaper/releases/latest">
    <img src="assets/download.png" alt="Download cachereaper for macOS" width="246" />
  </a>
</p>

<p align="center">
  <sub>
    Universal — Apple Silicon and Intel &nbsp;·&nbsp;
    <a href="#install">CLI install</a> &nbsp;·&nbsp;
    <a href="#tutorial">Tutorial</a>
  </sub>
</p>

Find and reclaim disk space from caches and build artifacts — with a risk tier on
every finding, an interactive picker, and guards that make it hard to delete
something you actually wanted.

Single file. No dependencies. Python 3.9+. macOS and Linux.

```
LOW RISK      pure caches, regenerate automatically   [5.0G]
  --------------------------------------------------------------------------
      1.2G        pnpm-store                 pnpm content store
      1.2G  x17   app-cache                  app HTTP cache
    800.1M        vscode-vsix                VS Code extension installers (already installed)
    595.3M        cargo-registry             cargo crate sources + archives

MEDIUM RISK   reinstallable, costs you time/bandwidth   [3.2G]
  --------------------------------------------------------------------------
    701.3M        nuget-packages             NuGet global packages
    255.2M  x7    node-modules               installed npm packages
     75.3M  x9    dist-dir                   dist output (git-ignored)

HIGH RISK     stateful or expensive - review each one   [1.8G]
  --------------------------------------------------------------------------
      1.4G        rustup-toolchains          rust toolchains
            ! prefer `rustup toolchain uninstall <old>` to keep the active one
```

## Why another cleaner

Most disk cleaners either delete a hardcoded list of paths, or ask you to trust a
GUI with `sudo`. cachereaper takes a different position:

- **Nothing is deleted without a rule**, and every rule carries a risk tier and a
  "here's how you get it back" note.
- **Build artifacts must prove what they are.** A `target/` directory is only a
  Rust build if `Cargo.toml` sits next to it. A `venv` is only a virtualenv if it
  contains `pyvenv.cfg`. Ambiguous names like `build/` and `dist/` are only
  claimed when **git already ignores them** — because that is the project telling
  you it is output, not source.
- **Dry-run is the default**, and `clean` always confirms.

## Install

**The desktop app.** One command, and it lands in `/Applications` ready to open:

```bash
curl -fsSL https://raw.githubusercontent.com/samreshan/cachereaper/main/install.sh -o install.sh
less install.sh          # it is 60 lines, most of them comments
bash install.sh
```

**If you download the `.dmg` by hand**, macOS will refuse to open it, and on
macOS 15 and newer there is no right-click → Open to get around that any more —
the only click-through left is System Settings → Privacy & Security → **Open
Anyway**, after a launch has already failed. One command avoids the trip:

```bash
# after dragging cachereaper out of the .dmg into Applications
xattr -dr com.apple.quarantine /Applications/cachereaper.app
```

<details>
<summary>Why macOS does this, and what the command actually does</summary>

The app is signed **ad-hoc** rather than with an Apple Developer ID, because a
Developer ID requires a paid Apple Developer Program membership. Ad-hoc is
enough to *run* — it is what lets the binary execute on Apple Silicon at all —
but it is not an identity, so Gatekeeper cannot attribute the app to anyone.

Separately, macOS tags every browser download with a `com.apple.quarantine`
extended attribute. Gatekeeper refuses quarantined apps that have no Developer
ID, and reports it as *"cachereaper is damaged and can't be opened"* — which is
its wording for *unidentified*, not for *corrupt*. Nothing is wrong with the
download.

`xattr -dr com.apple.quarantine` removes that tag. It is the same decision you
would be making in the Privacy & Security pane, made once and up front instead
of after a failed launch. `install.sh` does exactly this, plus the download and
the copy.

Two ways to avoid the question entirely: build from source with
`./gui/release.sh` — code you compiled yourself is never quarantined — or use
the CLI, which is a plain Python file and not subject to any of this.

The honest fix is notarisation, which needs the $99/year membership. If that
ever happens, the app will be signed and this section will disappear.
</details>

**The CLI** — one file, no dependencies, Python 3.9+:

```bash
git clone https://github.com/samreshan/cachereaper
install -m 755 cachereaper/cachereaper.py ~/.local/bin/cachereaper
```

Or run it in place: `python3 cachereaper.py scan`.

## Tutorial

A first run, start to finish. Nothing here deletes anything until step 4, and
step 4 asks first.

**1. Look, without touching.** `scan` is the default command and dry-run is the
default mode, so the bare binary is safe to type:

```bash
cachereaper
```

You get the low-risk tier only — the caches that regenerate themselves. Each row
is `size`, `xN` if the rule matched several places, the rule id, and what it
actually is. The `[5.0G]` after each heading is what that whole tier is worth.

**2. Widen the net.** Low risk is deliberately timid. Ask for more once you have
seen what it finds:

```bash
cachereaper scan --tier medium          # + node_modules, virtualenvs, package caches
cachereaper scan --tier high -v         # + toolchains and simulators, with paths
```

`-v` is the flag to reach for when a number looks wrong: it prints the individual
paths behind a rule instead of the total, so you can see *which* `node_modules`
is 2G. Two more that pay off on a crowded disk:

```bash
cachereaper scan --tier medium --stale-days 30    # only things untouched for a month
cachereaper scan --tier medium --min-size 100M    # only findings worth the trouble
```

**3. Pick what actually goes.** `select` opens the picker described
[below](#picking-what-to-remove) — low-risk groups start ticked, medium and high
start empty, so pressing `d` immediately does the conservative thing:

```bash
cachereaper select
```

**4. Reap.** `clean` prints what it is about to do and waits for you. High-risk
findings make you type a phrase rather than `y`:

```bash
cachereaper clean --tier low            # confirms, then deletes
cachereaper clean --tier medium --stale-days 30 --dry-run   # rehearse it first
```

Every deletion is written to `~/.cachereaper/reap-<timestamp>.jsonl` with the
path, the rule, the byte count, and the command that puts it back.

**5. Check the vendor commands.** For Docker, Colima, rustup, simctl and Time
Machine snapshots, a vendor command is genuinely safer than `rm -rf`, so
cachereaper prints the command instead of offering to delete the directory:

```bash
cachereaper tools
```

**6. Open the map.** The desktop app shows a folder as a treemap with the risk
tiers painted on top — big *and* safe to delete, rather than just big. It opens
by asking which folder; pick one, or hand it your home directory. Drill in by
clicking, press `s` to switch to Select mode, and drag a box to grab many blocks
at once. Full keys are in [The desktop app](#the-desktop-app).

## Usage

```bash
cachereaper                                  # scan, low-risk findings (default)
cachereaper scan --tier high -v              # everything, with individual paths
cachereaper select                           # scan, then pick what to remove
cachereaper clean --tier low                 # delete safe caches (confirms first)
cachereaper clean --tier medium --stale-days 30 --dry-run
cachereaper tools                            # safer vendor commands + full rule list
```

### Picking what to remove

`cachereaper select` opens a full-screen picker:

```
 cachereaper — select what to remove
 selected 5.0G of 10.0G   (78 paths)

 [x] >    1.2G        pnpm-store               pnpm content store
 [x] v    1.2G  x17   app-cache                app HTTP cache
       [x]  412.0M   12d  ~/Library/Application Support/Claude/Cache
       [ ]  188.3M    3d  ~/Library/Application Support/Code/Cache
 [ ] >  701.3M        nuget-packages           NuGet global packages
 [ ] >    1.4G        rustup-toolchains        rust toolchains

 space toggle   enter expand/collapse   a all   n none   1/2/3 tier low/med/high
 / filter   d done (proceed)   q cancel
```

Low-risk groups start selected; medium and high start empty, so pressing `d`
straight away does the safe thing. `--plain` gives a numbered picker instead, and
is chosen automatically when stdin is not a TTY.

### Useful flags

| flag | effect |
| --- | --- |
| `--tier low\|medium\|high` | highest risk tier to include (default `low`) |
| `--stale-days N` | only items untouched for N days |
| `--min-size 10M` | ignore anything smaller |
| `--only RULE...` / `--exclude RULE...` | filter by rule id |
| `--roots DIR...` | where to hunt for project artifacts (default `$HOME`) |
| `--system` | also scan `/Library/Caches`, `/private/var/folders` (needs sudo to delete) |
| `--json` | machine-readable scan output |
| `--dry-run` | print exactly what `clean` would remove |

## Risk tiers

| tier | meaning | examples |
| --- | --- | --- |
| **low** | pure cache, regenerates itself, costs you nothing | npm/pip/cargo caches, Electron app caches, `__pycache__`, Xcode DerivedData |
| **medium** | reinstallable, but costs time or bandwidth | `node_modules`, virtualenvs, NuGet/Maven/pub caches, git-ignored `dist/` |
| **high** | stateful or expensive — review individually | rustup toolchains, simulator devices, Xcode archives, Docker modules |

## What it detects

**Known cache locations** (~55 rules): npm, yarn, pnpm, bun, pip, uv, poetry,
cargo, go, gradle, maven, NuGet, composer, CocoaPods, SwiftPM, deno, Homebrew,
Playwright, Puppeteer, Prisma, Hardhat, node-gyp, Xcode DerivedData and archives,
CoreSimulator, VS Code caches, Electron app caches
(`Library/Application Support/*/Cache`, `Code Cache`, `GPUCache`,
`Service Worker/CacheStorage`), sandboxed app caches
(`Library/Containers/*/Data/Library/Caches`), and `Library/Caches/*`.

**Project build artifacts**, each gated on a marker:

| directory | claimed when |
| --- | --- |
| `target/` | `Cargo.toml` or `pom.xml` is a sibling |
| `node_modules/` | always (unambiguous) |
| `.venv/`, `venv/`, `env/` | contains `pyvenv.cfg` |
| `Pods/` | `Podfile` is a sibling |
| `vendor/` | `composer.json` is a sibling |
| `.next/`, `.nuxt/`, `.turbo/`, `.svelte-kit/`, `.astro/`, `.angular/`, `.vite/`, `.parcel-cache/` | `package.json` is a sibling |
| `.gradle/` | a `build.gradle*` / `settings.gradle*` is a sibling |
| `.dart_tool/` | `pubspec.yaml` is a sibling |
| `_build/`, `deps/` | `mix.exs` / `dune-project` is a sibling |
| `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.tox/`, `.nox/`, `.terraform/`, `DerivedData/`, `elm-stuff/` | by name |
| `build/`, `dist/`, `out/`, `obj/` | **only if git already ignores them** |

## Safety model

1. **Confined to `$HOME`** plus any roots you explicitly pass with `--roots`.
   `--system` paths additionally require running as root.
2. **Hard-blocked path components**, never candidates and re-checked before every
   delete: `.git`, `.hg`, `.svn`, `.ssh`, `.gnupg`, `Keychains`, `CloudStorage`,
   `Mobile Documents`, `*.photoslibrary`, and any directory starting with
   OneDrive / Google Drive / Dropbox / iCloud / Creative Cloud / Nextcloud / …
3. **Never follows symlinks, never crosses filesystems**, and never descends into
   a directory it has already claimed.
4. **Re-validated at delete time** — the path must still exist, still carry the
   name it had at scan time, and still fall inside the allowed roots. A scan
   result that goes stale is skipped, not deleted.
5. **Stateful data is not a rule at all**: VM disks (Colima/Lima), chat and
   session history, `Downloads`, and source directories are never offered.
6. **Everything is logged** to `~/.cachereaper/reap-<timestamp>.jsonl` with the
   path, rule, byte count, and restore command.
7. **High risk requires typing a phrase**, not just `y`.

For things where a vendor command is genuinely safer than `rm -rf` — Docker,
Colima, rustup, simctl, Time Machine local snapshots — `cachereaper tools` prints
the command instead of offering to delete the directory.

## The desktop app

A treemap of every file on disk, with the risk tiers painted on top.
GrandPerspective shows you what is big; cachereaper shows you what is big **and**
safe to delete.

It opens by asking what to look at rather than walking your disk uninvited —
choose a folder, or take the whole home directory. The walk then holds the
window with a live file and byte count until it has a tree to show; a home
directory of a million files takes about thirteen seconds. **Scan folder…** in
the toolbar repoints it later: an external drive, one project, `~/Library`. The
roots you actually scan are also what bounds deletion for the rest of the
session; cachereaper will not remove anything outside `$HOME` plus those.

[Download the `.dmg`](https://github.com/samreshan/cachereaper/releases/latest),
or build it yourself:

```bash
./gui/dev.sh ~/Programming      # run the map in a browser, no desktop build
./gui/dev.sh                    # your whole home directory

./gui/release.sh                # universal .app + .dmg, ready to hand to someone

# or just the binary, no bundle
cargo build --release --manifest-path gui/src-tauri/Cargo.toml
./gui/src-tauri/target/release/cachereaper-gui
```

| | |
| --- | --- |
| **Scan folder…** | choose a different root and rescan |
| click | drill into a folder |
| backspace / **↑** | go back up |
| **Select** mode (or `s`) | click blocks to select, drag a box to select many |
| ⌥click in Select mode | drill in instead of selecting |
| ⌘click in Explore mode | select the nearest claimed folder |
| esc | clear the selection |

Colour carries one meaning: risk tiers stay saturated, and anything the rules did
not claim is drained to a neutral grey so it recedes. The map answers "what can I
delete" rather than "what is on my disk".

Dragging a box across a `node_modules` means *that folder*, not *those 400 files*:
when every block under a folder falls inside the box, the folder replaces them.

### Architecture, and the one thing worth knowing

The rule table lives in `cachereaper.py` and nowhere else. `cachereaper dump-rules`
generates `gui/rules.generated.json`, which the Rust core embeds at compile time,
and CI fails if the committed copy drifts. The *guards* are logic rather than data,
so they exist in both languages — held honest by `tests/guard_vectors.json`, which
both the Python suite and `cargo test` assert against. A guard changed in one
language and not the other fails CI.

Deletion from the GUI goes through the same `validate_for_delete`, the same
allowed-roots confinement, and the same `~/.cachereaper/reap-*.jsonl` audit log as
the CLI. It runs over Tauri IPC, so there is no listening socket.

The webview's permissions are one line — `core:default` in
`src-tauri/capabilities/default.json` — and that is the whole grant. The scanner
and the deleter are the app's own commands, which the ACL does not gate; the
folder chooser is deliberately *not* exposed to the frontend. `pick_folder` opens
the dialog from Rust and returns a path, so the only file dialog the webview can
ever cause is one asking for a single directory. It cannot open a save panel, a
multi-select, or a file read.

**Blocks the rules do not claim can be selected**, which is a deliberate widening
of the CLI's "nothing without a rule" stance. They are labelled *unclassified*, the
panel warns that there is no restore path for them, and deleting them requires
typing a confirmation phrase exactly as high-risk findings do.

Scanning is a parallel walk building an arena tree of directories only, with file
lists read on demand. Measured on a 1.05M-file home directory: 1 thread 144s,
4 threads 28.6s, **8 threads 13.2s** (~80k files/s); more threads regress on
contention.

## Tests

```bash
python3 -m unittest discover -s tests -v          # CLI
cargo test --manifest-path gui/core/Cargo.toml    # scanner, guards, deletion
node gui/tests/treemap.test.mjs                   # treemap layout
```

Covers the path guards, delete-time re-validation, nested-candidate dedupe,
marker gating, gitignore gating, selection state, an end-to-end scan and delete
against fixture trees, and the squarified layout (proportional areas, non-overlap,
containment, aspect ratio, degenerate input).

## Contributing

New rules are the most useful contribution. A rule needs an id, a tier, a label,
and an honest `regen` string. If the directory name is ambiguous (something that
could plausibly be source), gate it behind a marker or `need_gitignored=True`
rather than claiming it by name.

## Brand

<img src="assets/reaper.png" alt="the cachereaper mark" width="76" />

A hooded reaper in a red cloak, drawn on a 32×33 pixel grid. It is the whole
identity: the wordmark is a display script and does not survive being set at
13px, so the app uses the mark alone and sets its name in the UI's own type.
The lockup is for the README, the site, and release art.

| | hex | role |
| --- | --- | --- |
| **brand** | `#ea1d1f` | the cloak. High risk, and the delete button |
| **brand-lit** | `#fe2d28` | the cloak's lit edge. Hover only |
| **bone** | `#fef9e2` | the mask. Type on top of the brand red |
| **ink** | `#230f0c` | the outline. A warm near-black, not `#000` |

**Red means risk, and nothing else.** The app's whole argument is that colour
carries one meaning, so the reaper's red doubles as the danger colour instead of
sitting next to a second, unrelated one: `--high`, the high-risk tier on the
treemap, and the delete button are all drawn from `--brand`. Selection stays
blue, because selecting something is not a statement about risk.

Two values are tuned rather than copied, both for contrast, and both documented
where they are set. `--high` is lifted to `#f0433c` on dark and dropped to
`#c8181a` on light. The delete button fills with `#d81a1c` — one step down from
the mark, because bone on `#ea1d1f` is 4.2:1 and the label is 13px; hover
returns it to the mark's exact value.

| file | what it is |
| --- | --- |
| `assets/reaper.svg` | the mark, traced to real `<rect>`s — 9KB, crisp at any size |
| `assets/reaper.png` | the mark at 512px, nearest-neighbour |
| `assets/logo.png` | full lockup, for light backgrounds |
| `assets/logo-dark.png` | same lockup with the wordmark in bone |
| `assets/download.png` | the README's download button. Ink ground, because a red mark on a red button disappears |
| `gui/dist/reaper.svg` | byte-identical copy of the mark. The GUI ships a `default-src 'self'` CSP and Tauri bundles `gui/dist` only, so the file has to live inside it |
| `gui/src-tauri/icons/` | app icon: the mark on `#15181d`, the app's own chrome |

The mark is a vector trace of the original pixel art, not a copy of the vendor
file. The supplied `.svg` exports are a base64 PNG in an `<svg>` wrapper, and the
lockup's `.svg` sets live text in *Genius Fraud Demo* — it renders as a fallback
font on any machine without it installed. Neither is safe to ship, so the mark
was traced back onto its grid and the lockup is used as a raster.

## License

MIT
