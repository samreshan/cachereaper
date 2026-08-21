# Releasing

## 1.6.0 — Trust and Control

Adds cancelable scans, explicit reclaimable/allocated/logical accounting,
searchable Map/List findings, global and profile exclusions, reusable scan
profiles, and durable local cleanup receipts with History. No telemetry,
scheduled cleanup, vendor cleanup automation, or background deletion was added.

Tag it and push. The rest is CI.

```bash
git tag -a v1.6.0 -m "What changed, in a sentence or three."
git push origin v1.6.0
```

The tag message is not decoration: it becomes the release note shown inside the
app when an installed copy is offered the update. An unannotated tag falls back
to `cachereaper <version>`.

Bump these together first — CI does not check them against the tag, and a
version that disagrees with itself ships without complaint:

* `cachereaper.py` — `VERSION`
* `pyproject.toml` — `version`
* `gui/src-tauri/tauri.conf.json` — `version` (this is the one the updater
  compares against, so an app that was not bumped will never see the release)
* `gui/src-tauri/Cargo.toml` and `gui/core/Cargo.toml` — `version`

`workflow_dispatch` on the release workflow builds both platforms and keeps the
bundles as workflow artifacts without publishing anything, which is how to prove
a change to the build before a tag exists to attach it to.

## The signing key

Updates are signed with minisign. The app carries the public half compiled in
(`plugins.updater.pubkey` in `tauri.conf.json`) and refuses anything that does
not match it, so the private half has to be available to CI:

```bash
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/cachereaper.key
```

The key was generated with an empty password, so `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
does not need to be set. If you regenerate the pair with one, set it too.

**Keep `~/.tauri/cachereaper.key`.** It is not in the repository and cannot be
recovered. Losing it means every installed copy stops being able to update:
the only way out is a new keypair in a new release, which nobody currently
running the app can be offered — they would each have to reinstall by hand.

Generating a replacement pair, if it ever comes to that:

```bash
cargo tauri signer generate -w ~/.tauri/cachereaper.key
```

Then put the contents of `~/.tauri/cachereaper.key.pub` into `tauri.conf.json`
and the private half into the secret above.

## What a release contains

| asset | for |
| --- | --- |
| `cachereaper-macos-universal.dmg` | a person downloading it |
| `cachereaper-windows-x64-setup.exe`, `.msi` | the same, on Windows |
| `cachereaper-macos-universal.app.tar.gz` | the macOS update payload |
| `latest.json` | what installed copies read to find all of the above |

`latest.json` is assembled by the publish job from a signature fragment each
build job emits, and the job fails rather than publishing a manifest that is
missing a platform.

Updater artifacts are switched on by a `--config` flag in CI rather than in
`tauri.conf.json`, so building from source — `gui/release.sh`, or plain
`cargo tauri build` — never asks for a private key.

## Anyone already running an older build

Only builds from this release onwards can update themselves; there was no
updater in 1.4.0 and earlier. Those copies have to be replaced once, the old
way, before they can start doing it themselves.
