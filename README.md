# cachereaper

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

```bash
git clone https://github.com/<you>/cachereaper
install -m 755 cachereaper/cachereaper.py ~/.local/bin/cachereaper
```

Or run it in place: `python3 cachereaper.py scan`.

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

```bash
./gui/dev.sh ~/Programming      # run the map in a browser, no desktop build
./gui/dev.sh                    # your whole home directory

cargo build --release --manifest-path gui/src-tauri/Cargo.toml
./gui/src-tauri/target/release/cachereaper-gui
```

| | |
| --- | --- |
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

## License

MIT
