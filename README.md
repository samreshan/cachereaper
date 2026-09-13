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

**Version 2.0** adds explicit whole-disk and all-files inspection, locally proven
duplicates, recoverable personal-file actions, snapshot trends, typed Ask and
Plan workspaces, and bounded storage intelligence. Read the complete
[2.0 release notes](RELEASE_NOTES.md).

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
| `--profile NAME_OR_ID` | use one saved root and its exclusions (cannot be combined with `--roots`) |
| `--exclude-path PATH...` | additional directories not to traverse in this scan |
| `--ignore-saved-exclusions` | ignore saved global/profile exclusions for a reproducible scan |
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

### Scan modes

The v2 scanner separates three levels of inspection so a storage overview does
not silently become a content scan:

| mode | reads | produces |
| --- | --- | --- |
| **Cache** | directory metadata and rule markers | known caches and build artifacts; the fast default |
| **Whole Disk** | file metadata, never contents | category totals, largest files, old large files, and the treemap |
| **All Files** | Whole Disk metadata plus candidate contents | locally proven exact duplicate groups using a partial filter followed by full SHA-256 hashes |

Whole Disk insights are read-only. Personal files are never sent through the
cache deletion path. In All Files mode, one member of a fully verified duplicate
group can be moved through macOS's native Trash API (the default) or into a
same-volume CacheReaper quarantine vault. If native Trash is unavailable, an
explicitly confirmed action falls back to quarantine instead of deleting the
file directly. Cache Scan retains no file-level inventory.

Both personal-file actions are authorized only by the newest completed All Files
scan. CacheReaper rehashes the selected file and requires another unchanged copy,
then durably records its intent before asking the filesystem to move anything.
Native Trash remains recoverable through Finder; quarantine remains recoverable
inside CacheReaper and does not free space until a separately confirmed expiry.

Quarantine is authorized only by the newest completed All Files scan. CacheReaper
rehashes the selected file and requires another unchanged copy before moving it
atomically into `<scan root>/.cachereaper-quarantine`. It first persists an
append-only manifest under `~/.cachereaper/quarantine-*.jsonl`, invalidates the
scan evidence after a move, never overwrites an occupied restore path, and can
recover a move interrupted between its planned and completed manifest events.

Quarantine retention defaults to 30 days and can be changed to 7, 30, 90, 365,
or **Never**. Nothing expires automatically: after the deadline, the history UI
can expose a permanent-expiry action that requires typing an item-specific phrase.
Immediately before deletion, CacheReaper rehashes the quarantined file and
requires an unchanged peer captured from the original duplicate group. Legacy
records without that evidence remain restorable but cannot be expired.

The Action History sheet projects cleanup receipts, quarantine manifests, and
native Trash transaction events into one chronological audit view. Interrupted
moves are never presented as successful: they become an explicit
`recovery-required` state with the correct recovery location.

Completed Cache, Whole Disk, and All Files scans also publish immutable local
summaries under `~/.cachereaper/index/`. A later scan shows allocated, logical,
file-count, category, and directory growth against the latest snapshot for the
same root, filesystem identity, and mode. Only the newest 20 snapshots per
root/mode are retained.

Deep Scan caches partial and complete SHA-256 results by filesystem identity,
logical size, and high-resolution modification time. Unchanged candidates avoid
being read again; mutations get a new key and are rehashed. The cache is bounded
and age-pruned. A corrupt or newer hash-index schema produces a visible warning
and is rebuilt; unreadable snapshot records are ignored. Neither can block
startup or become action authority. Cross-platform
filesystem notifications invalidate duplicate evidence and reveal a snapshot
refresh control whenever the scanned root changes.

The **Ask** workspace compiles a deliberately small natural-language grammar
into a visible typed filter over the current evidence. It accepts size, age,
category, path, risk, insight kind, recovery method, and provenance clauses;
unknown grammar and command-like input fail closed. The **Plan** workspace turns
a target size and Safest, Balanced, Maximum, or Fastest Recovery policy into a
deterministic, snapshot-bound review plan. Plans never execute themselves,
never add paths, and distinguish immediately reclaimable cache space from space
that remains occupied until system Trash is emptied. Protected reference roots
are excluded from duplicate actions.

Optional local-model support is compiled with the `local-ai` Cargo feature. Its
adapter can return only bounded rankings and explanations for existing insight
IDs. Strict JSON validation rejects unknown fields, paths, action requests,
unknown IDs, duplicate IDs, malformed output, and oversized text. The model is
presentation-only: typed scanner and rule evidence remains the sole authority
for every permitted action, and deterministic explanations work without a
model.

### Advanced local intelligence (M6)

All Files scans now add bounded, local similar-media analysis. Images use a
decoded perceptual difference hash; video and audio use eight evenly spaced,
streamed samples. Results expose an algorithm and minimum similarity score, are
clearly labelled **review only**, and never inherit the exact-duplicate Trash or
quarantine actions. The analyzer considers at most 256 candidates and 64 groups
per media kind, rejects files over 512 MB, caps decoded images at 40 megapixels
and 192 MB of decoder allocation, and discards partial groups after cancellation.

Whole Disk and All Files scans compare top-level application cache/data owners
with a bounded local catalogue of installed apps. A match is evidence of current
ownership; a miss is only a **possible leftover** because portable and custom
installs may not appear in the catalogue. These hints are reveal-only and never
authorize deletion.

Project manifests and lockfiles identify regenerable rule-backed artifacts for
Rust, JavaScript, Python, JVM, Swift, CocoaPods, Go, Dart, and Elixir projects.
The estimate reports artifact bytes, rough rebuild time, and an upper-bound
download size. It does not inspect working-tree changes, and source files plus
repository metadata remain outside the action model.

Once a root and scan mode have at least two local snapshots spanning an hour,
CacheReaper derives a robust median growth rate and an estimated date for the
volume to reach 10% free space. With three or more snapshots it also flags large
category or directory jumps against the prior median. Forecasts and anomalies
are explanatory evidence, not cleanup authority.

The `offload-connectors` Cargo feature exposes a provider-neutral connector
contract. Builds configure no cloud provider by default and perform no upload.
Before any future provider receives an item, the core creates a tamper-evident
disclosure naming the selected files, destination, estimated bytes, and data
leaving the device, then requires its exact confirmation phrase. Connector
receipts are schema-checked and cannot create local deletion actions.

Folders designated as **immutable reference roots** remain in scans and can act
as master copies when proving duplicates. CacheReaper blocks cache deletion,
quarantine, restore, and deletion of any ancestor folder that would modify a
reference root. These boundaries are shared by the desktop app and CLI; ignoring
saved scan exclusions never disables them. Manage them under **Profiles,
Reference Roots & Exclusions**.

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

### Scan accounting, profiles, and cancellation

The Map is always sized by **reclaimable bytes**: the scanner’s conservative
estimate of blocks that deleting a file can release. Scan Health separately
shows **allocated-reference bytes** (`st_blocks`-style references), **logical
bytes** (file lengths), and shared/snapshot bytes where the filesystem exposes
them. Sparse files, cloud placeholders, hard links, APFS clones, and snapshots
mean those values need not agree or fit neatly inside physical capacity. An
impossible total is shown as a warning and is never silently clamped.

Profiles save one absolute root plus profile-specific path and rule exclusions.
Global exclusions apply everywhere. Path exclusions are empty visible
boundaries that are never opened; rule exclusions leave their bytes on the map
but suppress cleanup suggestions. Paths are normalized lexically without
following symlinks. A running scan can be cancelled; all workers finish and the
partial tree is discarded, leaving the previous result in place after a rescan.
The optional fields in `~/.cachereaper/config.json` are
`global_excluded_paths`, `global_excluded_rules`, `profiles` (each with stable
`id`, unique `name`, absolute `root`, `excluded_paths`, and `excluded_rules`),
and `last_profile_id`. Older configs migrate through defaults without rewriting
the access or update preferences already stored there.

### Updates

The app asks the release page whether there is a newer build as soon as it
opens, before a folder is chosen or a scan begins, and says nothing unless there
is. When there is, the home screen names the version and offers to install it —
one click, and it downloads, replaces itself and restarts. The same card stays
available in the results panel after a scan. Nothing about your machine is sent,
and nothing is installed without being asked for: this tool deletes files, so
the binary that does that is not something to swap out quietly.

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
6. **Every real cleanup gets a durable receipt before deletion starts** in
   `~/.cachereaper/receipt-<milliseconds>-<pid>-<counter>.jsonl`. It records each
   removed or skipped target, the scanner estimate, and a separate signed,
   best-effort system-wide free-space delta. Dry runs create no receipt.
7. **High risk requires typing a phrase**, not just `y`.

Where a vendor command is safer than `rm -rf` — Docker, Colima, rustup, simctl,
Time Machine snapshots — `cachereaper tools` prints the command instead.

Cleanup History is local, has no telemetry or network submission, and is kept
until explicitly cleared. Receipts are an audit trail, not undo; deletion is
still permanent. Older `reap-*.jsonl` logs remain readable as legacy receipts,
and interrupted/truncated sessions are marked incomplete.

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
node gui/tests/v16.test.mjs                       # findings, health, receipts, DOM contracts
```

New rules are the most useful contribution. A rule needs an id, a tier, a label,
and an honest `regen` string. If the name is ambiguous, gate it behind a marker
or `need_gitignored=True` rather than claiming it outright.

## License

MIT
