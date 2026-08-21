#!/usr/bin/env python3
"""
cachereaper - find and reclaim disk space from caches and build artifacts.

Design rules:
  * Dry-run is the default. `clean` requires an explicit confirmation.
  * Every candidate carries a RISK TIER (low / medium / high) and a "how to
    regenerate" note. Nothing is deleted without a matching rule.
  * Build artifacts are only offered when a project marker proves what they are
    (target/ next to Cargo.toml, node_modules/ next to package.json, a venv with
    pyvenv.cfg, build/ that git already ignores...).
  * Stateful things (VM disks, chat history, source, cloud-sync folders, .git,
    keys) are never rules and are additionally blocked by a path guard.

No third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.6.0"
REPO = "samreshan/cachereaper"
HOME = Path.home()
LOG_DIR = HOME / ".cachereaper"

# Which set of rules applies here. A cache lives somewhere different on each
# operating system — ~/Library/Caches/pip, ~/.cache/pip and
# %LOCALAPPDATA%\pip\Cache are the same cache — so a rule says where it is true
# and the ones that cannot apply are never probed.
PLATFORM = "macos" if sys.platform == "darwin" else "windows" if os.name == "nt" else "linux"

TIER_RANK = {"low": 0, "medium": 1, "high": 2}
TIER_ORDER = ("low", "medium", "high")

# ---------------------------------------------------------------------------
# hard guards - these never become candidates and are re-checked before delete
# ---------------------------------------------------------------------------

FORBIDDEN_PARTS = {
    ".git", ".hg", ".svn", ".ssh", ".gnupg", "Keychains", "CloudStorage",
    "Photos Library.photoslibrary", "Mobile Documents",
}

CLOUD_DIR_HINTS = (
    "onedrive", "google drive", "dropbox", "icloud", "creative cloud",
    "pcloud", "mega", "megasync", "sync.com", "box sync", "nextcloud",
)


def _looks_like_cloud_dir(name: str) -> bool:
    """True for 'OneDrive - Acme' and 'Google Drive', false for 'megaproject'.

    A bare prefix test would swallow any directory that merely starts with one of
    these words, so a hint only matches at a name boundary.
    """
    low = name.lower()
    return any(low == hint or low.startswith(hint + " ") or low.startswith(hint + "-")
               for hint in CLOUD_DIR_HINTS)

# Never descend into these during the project walk (top-level of a root).
#
# AppData earns its place the same way Library does, and more urgently: a
# Windows app installed under AppData\Local\Programs ships its own node_modules,
# which the artifact rules would otherwise claim as "installed npm packages" and
# offer to delete out from under a working program.
SKIP_TOP_LEVEL = {
    "Library", "Applications", "Movies", "Music", "Pictures", "Public",
    ".Trash", "Virtual Machines.localized", "AppData",
}

# ---------------------------------------------------------------------------
# static cache locations
# fields: id, tier, glob (relative to HOME unless absolute), children?, label,
#         regen, warn, os
# ordered specific -> generic; first rule to claim a path wins
#
# `os` is "any" when the path is the same everywhere, which is most of the
# HOME-relative dotfile caches — ~/.cargo/registry and ~/.m2/repository are
# spelled identically on all three. Anything under Library/ or AppData/ is
# named for the one it belongs to.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StaticRule:
    id: str
    tier: str
    glob: str
    label: str
    regen: str
    children: bool = False
    warn: str = ""
    system: bool = False
    os: str = "any"          # any | macos | windows | linux

    def applies_here(self) -> bool:
        return self.os in ("any", PLATFORM)


S = StaticRule
STATIC_RULES = [
    # --- package manager caches (pure download caches) ---------------------
    S("npm-npx", "low", ".npm/_npx", "npx one-off package downloads", "re-downloaded on next npx"),
    S("npm-cache", "low", ".npm/_cacache", "npm content cache", "npm cache clean --force"),
    S("npm-logs", "low", ".npm/_logs", "npm debug logs", "n/a"),
    S("yarn-cache", "low", ".yarn/cache", "yarn cache", "yarn install"),
    S("yarn-cache2", "low", "Library/Caches/Yarn", "yarn global cache", "yarn install", os="macos"),
    S("pnpm-store", "low", "Library/pnpm/store", "pnpm content store", "pnpm install", os="macos"),
    S("bun-cache", "low", ".bun/install/cache", "bun install cache", "bun install"),
    S("pip-cache", "low", "Library/Caches/pip", "pip wheel cache", "pip cache purge", os="macos"),
    S("pip-cache2", "low", ".cache/pip", "pip wheel cache", "pip cache purge"),
    S("uv-cache", "low", ".cache/uv", "uv package cache", "uv cache clean"),
    S("poetry-cache", "low", "Library/Caches/pypoetry", "poetry cache", "poetry cache clear --all .", os="macos"),
    S("cargo-registry", "low", ".cargo/registry", "cargo crate sources + archives", "cargo build re-downloads"),
    S("cargo-git", "low", ".cargo/git", "cargo git checkouts", "cargo build re-downloads"),
    S("go-build", "low", "Library/Caches/go-build", "go build cache", "go build", os="macos"),
    S("gradle-cache", "low", ".gradle/caches", "gradle dependency cache", "gradle build"),
    S("gradle-daemon", "low", ".gradle/daemon", "gradle daemon logs", "n/a"),
    S("composer-cache", "low", "Library/Caches/composer", "composer cache", "composer install", os="macos"),
    S("composer-cache2", "low", ".composer/cache", "composer cache", "composer install"),
    S("cocoapods-cache", "low", "Library/Caches/CocoaPods", "cocoapods spec cache", "pod install", os="macos"),
    S("node-gyp", "low", "Library/Caches/node-gyp", "node-gyp headers", "re-downloaded on build", os="macos"),
    S("puppeteer", "low", ".cache/puppeteer", "puppeteer chromium builds", "re-downloaded on use"),
    S("playwright", "low", "Library/Caches/ms-playwright", "playwright browsers", "npx playwright install", os="macos"),
    S("playwright-go", "low", "Library/Caches/ms-playwright-go", "playwright-go browsers", "re-downloaded on use", os="macos"),
    S("prisma", "low", ".cache/prisma", "prisma engines", "re-downloaded on generate"),
    S("hardhat", "low", "Library/Caches/hardhat-nodejs", "hardhat compiler cache", "re-downloaded on compile", os="macos"),
    S("homebrew-cache", "low", "Library/Caches/Homebrew", "homebrew downloads", "brew cleanup -s --prune=all", os="macos"),
    S("swiftpm-cache", "low", "Library/Caches/org.swift.swiftpm", "SwiftPM dependency cache", "swift build", os="macos"),
    S("deno-cache", "low", "Library/Caches/deno", "deno module cache", "deno cache", os="macos"),
    S("flutter-tool", "low", ".dart-tool", "dart tool state", "flutter pub get"),

    # --- AI / editor tool runtimes (re-downloaded on next launch) ----------
    S("codex-runtimes", "low", ".cache/codex-runtimes", "codex runtime installs", "re-downloaded by codex"),
    S("codex-packages", "medium", ".codex/packages", "codex packages", "re-downloaded by codex"),
    S("claude-vm-bundles", "medium", "Library/Application Support/Claude/vm_bundles",
      "Claude Desktop VM images", "re-downloaded on demand (large)", os="macos"),
    S("antigravity-backup", "medium", ".gemini/antigravity-backup", "stale Antigravity IDE backup", "n/a"),
    S("vscode-vsix", "low", "Library/Application Support/Code/CachedExtensionVSIXs",
      "VS Code extension installers (already installed)", "n/a", os="macos"),
    S("vscode-cacheddata", "low", "Library/Application Support/Code/CachedData",
      "VS Code compiled JS cache", "rebuilt on launch", os="macos"),

    # --- Xcode / iOS -------------------------------------------------------
    S("xcode-deriveddata", "low", "Library/Developer/Xcode/DerivedData",
      "Xcode DerivedData", "rebuilt on next build", children=True, os="macos"),
    S("xcode-logs", "low", "Library/Developer/Xcode/iOS Device Logs", "device logs", "n/a", os="macos"),
    S("simulator-caches", "low", "Library/Developer/CoreSimulator/Caches",
      "simulator caches", "rebuilt on launch", os="macos"),
    S("simulator-devices", "high", "Library/Developer/CoreSimulator/Devices",
      "simulator devices + their data", "xcrun simctl delete unavailable (safer)",
      warn="wipes simulator state; prefer `xcrun simctl delete unavailable`", os="macos"),
    S("xcode-archives", "high", "Library/Developer/Xcode/Archives",
      "Xcode archives (shipped builds, dSYMs)", "cannot be regenerated",
      warn="contains dSYMs needed to symbolicate released builds", os="macos"),

    # --- Electron / app caches (generic globs) -----------------------------
    S("app-cache", "low", "Library/Application Support/*/Cache", "app HTTP cache", "rebuilt on launch", os="macos"),
    S("app-code-cache", "low", "Library/Application Support/*/Code Cache", "app code cache", "rebuilt on launch", os="macos"),
    S("app-gpu-cache", "low", "Library/Application Support/*/GPUCache", "app GPU shader cache", "rebuilt on launch", os="macos"),
    S("app-cachestorage", "low", "Library/Application Support/*/Service Worker/CacheStorage",
      "service worker cache", "rebuilt on launch", os="macos"),
    S("container-cache", "low", "Library/Containers/*/Data/Library/Caches",
      "sandboxed app cache", "rebuilt on launch", os="macos"),

    # --- Windows: package managers -----------------------------------------
    # Everything Windows keeps lives under AppData, split between Local (this
    # machine) and Roaming (follows the user). Caches belong in Local and mostly
    # are; the ones that landed in Roaming are there because the app put them
    # there, not because they should follow you.
    S("npm-cache-win", "low", "AppData/Local/npm-cache", "npm content cache",
      "npm cache clean --force", os="windows"),
    S("yarn-cache-win", "low", "AppData/Local/Yarn/Cache", "yarn cache", "yarn install", os="windows"),
    S("yarn-berry-win", "low", "AppData/Local/Yarn/Berry/cache", "yarn berry global cache",
      "yarn install", os="windows"),
    S("pnpm-store-win", "low", "AppData/Local/pnpm/store", "pnpm content store", "pnpm install", os="windows"),
    S("pip-cache-win", "low", "AppData/Local/pip/Cache", "pip wheel cache", "pip cache purge", os="windows"),
    S("uv-cache-win", "low", "AppData/Local/uv/cache", "uv package cache", "uv cache clean", os="windows"),
    S("poetry-cache-win", "low", "AppData/Local/pypoetry/Cache", "poetry cache",
      "poetry cache clear --all .", os="windows"),
    S("virtualenv-win", "low", "AppData/Local/pypa/virtualenv", "virtualenv seed wheels",
      "re-downloaded on next venv", os="windows"),
    S("go-build-win", "low", "AppData/Local/go-build", "go build cache", "go build", os="windows"),
    S("composer-cache-win", "low", "AppData/Local/Composer", "composer cache", "composer install", os="windows"),
    S("nuget-http-win", "low", "AppData/Local/NuGet/v3-cache", "NuGet HTTP cache", "dotnet restore", os="windows"),
    S("nuget-plugins-win", "low", "AppData/Local/NuGet/plugins-cache", "NuGet plugin cache",
      "dotnet restore", os="windows"),
    S("node-gyp-win", "low", "AppData/Local/node-gyp/Cache", "node-gyp headers",
      "re-downloaded on build", os="windows"),
    S("playwright-win", "low", "AppData/Local/ms-playwright", "playwright browsers",
      "npx playwright install", os="windows"),
    S("deno-win", "low", "AppData/Local/deno", "deno module cache", "deno cache", os="windows"),
    S("electron-win", "low", "AppData/Local/electron/Cache", "Electron binary downloads",
      "re-downloaded on build", os="windows"),
    S("electron-builder-win", "low", "AppData/Local/electron-builder/Cache",
      "electron-builder downloads", "re-downloaded on build", os="windows"),
    S("pub-cache-win", "medium", "AppData/Local/Pub/Cache", "Dart/Flutter package cache",
      "flutter pub get", os="windows"),

    # --- Windows: editors and IDEs -----------------------------------------
    S("vscode-vsix-win", "low", "AppData/Roaming/Code/CachedExtensionVSIXs",
      "VS Code extension installers (already installed)", "n/a", os="windows"),
    S("vscode-cacheddata-win", "low", "AppData/Roaming/Code/CachedData",
      "VS Code compiled JS cache", "rebuilt on launch", os="windows"),
    S("vs-packages-win", "medium", "AppData/Local/Microsoft/VisualStudio/Packages",
      "Visual Studio installer package cache", "re-downloaded if VS is repaired", os="windows"),
    S("jetbrains-caches-win", "low", "AppData/Local/JetBrains/*/caches",
      "JetBrains IDE index caches", "rebuilt on next index", os="windows"),
    S("unity-cache-win", "low", "AppData/Local/Unity/cache", "Unity asset + package cache",
      "re-downloaded by Unity", os="windows"),

    # --- Windows itself ----------------------------------------------------
    S("crash-dumps-win", "low", "AppData/Local/CrashDumps", "application crash dumps", "n/a", os="windows"),
    S("wer-archive-win", "low", "AppData/Local/Microsoft/Windows/WER/ReportArchive",
      "Windows error reports (archived)", "n/a", os="windows"),
    S("wer-queue-win", "low", "AppData/Local/Microsoft/Windows/WER/ReportQueue",
      "Windows error reports (queued)", "n/a", os="windows"),
    S("inetcache-win", "low", "AppData/Local/Microsoft/Windows/INetCache",
      "WinINet download cache", "rebuilt on use", os="windows"),
    S("explorer-thumbs-win", "low", "AppData/Local/Microsoft/Windows/Explorer",
      "Explorer thumbnail + icon caches", "rebuilt by Explorer", os="windows",
      warn="the .db files are locked while Explorer is running"),

    # --- Windows: Electron / app caches (generic globs) --------------------
    S("app-cache-win", "low", "AppData/Roaming/*/Cache", "app HTTP cache", "rebuilt on launch", os="windows"),
    S("app-code-cache-win", "low", "AppData/Roaming/*/Code Cache", "app code cache",
      "rebuilt on launch", os="windows"),
    S("app-gpu-cache-win", "low", "AppData/Roaming/*/GPUCache", "app GPU shader cache",
      "rebuilt on launch", os="windows"),
    S("app-cachestorage-win", "low", "AppData/Roaming/*/Service Worker/CacheStorage",
      "service worker cache", "rebuilt on launch", os="windows"),
    S("local-app-cache-win", "low", "AppData/Local/*/Cache", "app cache", "rebuilt on launch", os="windows"),
    S("local-app-code-cache-win", "low", "AppData/Local/*/Code Cache", "app code cache",
      "rebuilt on launch", os="windows"),
    S("local-app-gpu-cache-win", "low", "AppData/Local/*/GPUCache", "app GPU shader cache",
      "rebuilt on launch", os="windows"),

    # --- big-ticket toolchain stores (reinstallable, but slow) -------------
    S("go-modcache", "medium", "go/pkg/mod", "go module cache", "go mod download"),
    S("maven-repo", "medium", ".m2/repository", "maven local repository", "mvn re-downloads"),
    S("nuget-packages", "medium", ".nuget/packages", "NuGet global packages", "dotnet restore"),
    S("pub-cache", "medium", ".pub-cache", "Dart/Flutter package cache", "flutter pub get"),
    S("rustup-toolchains", "high", ".rustup/toolchains", "rust toolchains",
      "rustup toolchain install <ver>", warn="prefer `rustup toolchain uninstall <old>` to keep the active one"),
    S("docker-modules", "high", ".docker/modules", "Docker Desktop modules",
      "reinstalled by Docker Desktop", warn="only when Docker is not running"),

    # --- generic catch-alls (run last) -------------------------------------
    S("xdg-cache", "low", ".cache", "XDG cache entries", "app-specific", children=True),
    S("macos-user-cache", "low", "Library/Caches", "macOS per-app user caches",
      "rebuilt on launch", children=True, os="macos"),
    S("windows-temp", "medium", "AppData/Local/Temp", "per-user temp files",
      "rebuilt as needed", children=True, os="windows",
      warn="an entry can belong to a running installer or app"),
    S("trash", "medium", ".Trash", "Trash contents", "cannot be undone", children=True,
      warn="this is your Trash - check it before emptying", os="macos"),

    # --- system-wide (needs --system, and root to actually delete) ---------
    S("system-cache", "high", "/Library/Caches", "system-wide caches",
      "rebuilt by macOS", children=True, system=True, os="macos",
      warn="requires sudo; some entries are in use"),
    S("tmp-folders", "high", "/private/var/folders/*/*/C", "per-user temp caches",
      "rebuilt by macOS", system=True, os="macos", warn="requires sudo; may be in active use"),
]

# ---------------------------------------------------------------------------
# project build artifacts - only claimed when a marker proves the type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArtifactRule:
    id: str
    tier: str
    label: str
    regen: str
    markers: tuple = ()          # sibling files that must exist
    contains: tuple = ()         # entries that must exist *inside* the dir
    need_gitignored: bool = False  # only claim if git already ignores it


A = ArtifactRule
ARTIFACT_RULES: dict[str, list[ArtifactRule]] = {
    "target": [
        A("rust-target", "low", "Rust build output", "cargo build", markers=("Cargo.toml",)),
        A("maven-target", "low", "Maven build output", "mvn package", markers=("pom.xml",)),
    ],
    "node_modules": [
        A("node-modules", "medium", "installed npm packages", "npm install / bun install"),
    ],
    "__pycache__": [A("pycache", "low", "Python bytecode", "regenerated on import")],
    ".pytest_cache": [A("pytest-cache", "low", "pytest cache", "regenerated on test run")],
    ".mypy_cache": [A("mypy-cache", "low", "mypy cache", "regenerated on check")],
    ".ruff_cache": [A("ruff-cache", "low", "ruff cache", "regenerated on lint")],
    ".tox": [A("tox", "low", "tox environments", "tox recreates")],
    ".nox": [A("nox", "low", "nox environments", "nox recreates")],
    ".venv": [A("venv", "medium", "Python virtualenv", "python -m venv .venv && pip install -r requirements.txt",
                contains=("pyvenv.cfg",))],
    "venv": [A("venv", "medium", "Python virtualenv", "python -m venv venv && pip install -r requirements.txt",
               contains=("pyvenv.cfg",))],
    "env": [A("venv", "medium", "Python virtualenv", "python -m venv env && pip install -r requirements.txt",
              contains=("pyvenv.cfg",))],
    ".next": [A("next-build", "low", "Next.js build cache", "next build", markers=("package.json",))],
    ".nuxt": [A("nuxt-build", "low", "Nuxt build output", "nuxt build", markers=("package.json",))],
    ".turbo": [A("turbo-cache", "low", "Turborepo cache", "turbo run", markers=("package.json",))],
    ".svelte-kit": [A("sveltekit", "low", "SvelteKit build output", "vite build", markers=("package.json",))],
    ".astro": [A("astro", "low", "Astro build output", "astro build", markers=("package.json",))],
    ".angular": [A("angular-cache", "low", "Angular build cache", "ng build", markers=("package.json",))],
    ".parcel-cache": [A("parcel-cache", "low", "Parcel cache", "parcel build", markers=("package.json",))],
    ".vite": [A("vite-cache", "low", "Vite cache", "vite", markers=("package.json",))],
    ".expo": [A("expo-cache", "low", "Expo cache", "expo start", markers=("package.json",))],
    ".dart_tool": [A("dart-tool", "low", "Dart tool cache", "flutter pub get", markers=("pubspec.yaml",))],
    ".gradle": [A("project-gradle", "low", "project Gradle cache", "gradle build",
                  markers=("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"))],
    ".terraform": [A("terraform", "medium", "Terraform providers/modules", "terraform init")],
    "Pods": [A("cocoapods", "medium", "CocoaPods dependencies", "pod install", markers=("Podfile",))],
    "DerivedData": [A("project-deriveddata", "low", "Xcode DerivedData", "rebuilt on build")],
    "vendor": [A("composer-vendor", "medium", "Composer dependencies", "composer install",
                 markers=("composer.json",))],
    "elm-stuff": [A("elm-stuff", "low", "Elm build artifacts", "elm make", markers=("elm.json",))],
    "_build": [A("elixir-build", "low", "Elixir/OCaml build output", "mix compile",
                 markers=("mix.exs", "dune-project"))],
    "deps": [A("elixir-deps", "medium", "Elixir dependencies", "mix deps.get", markers=("mix.exs",))],
    # gitignore-gated: ambiguous names that are often real source
    "build": [A("build-dir", "medium", "build output (git-ignored)", "project build command",
                need_gitignored=True)],
    "dist": [A("dist-dir", "medium", "dist output (git-ignored)", "project build command",
               need_gitignored=True)],
    "out": [A("out-dir", "medium", "out output (git-ignored)", "project build command",
              need_gitignored=True)],
    "obj": [A("dotnet-obj", "low", "MSBuild intermediates (git-ignored)", "dotnet build",
              need_gitignored=True)],
}

# hidden dirs we still walk into as candidates
HIDDEN_ARTIFACTS = {n for n in ARTIFACT_RULES if n.startswith(".")}

# ---------------------------------------------------------------------------
# safer vendor commands - reported by `cachereaper tools`
# ---------------------------------------------------------------------------

TOOL_COMMANDS = [
    ("macOS", "tmutil listlocalsnapshots /", "list local Time Machine snapshots (often many GB)"),
    ("macOS", "sudo tmutil deletelocalsnapshots <date>", "delete a local snapshot"),
    ("Docker", "docker system prune -af --volumes", "reclaim inside the VM without destroying it"),
    ("Colima", "colima stop && colima delete", "destroys the VM disk AND all images/containers"),
    ("Homebrew", "brew cleanup -s --prune=all", "old versions + stale downloads"),
    ("npm", "npm cache clean --force", ""),
    ("yarn", "yarn cache clean", ""),
    ("pnpm", "pnpm store prune", ""),
    ("bun", "bun pm cache rm", ""),
    ("pip", "pip cache purge", ""),
    ("uv", "uv cache clean", ""),
    ("poetry", "poetry cache clear --all .", ""),
    ("Go", "go clean -modcache -cache", ""),
    ("Gradle", "./gradlew --stop && rm -rf ~/.gradle/caches", ""),
    ("Rust", "rustup toolchain list && rustup toolchain uninstall <old>", "keeps the active toolchain"),
    ("Xcode", "xcrun simctl delete unavailable", "removes simulators for uninstalled runtimes"),
    ("Flutter", "flutter clean", "per-project"),
]

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


BOLD = lambda s: c(s, "1")
DIM = lambda s: c(s, "2")
GREEN = lambda s: c(s, "32")
YELLOW = lambda s: c(s, "33")
RED = lambda s: c(s, "31")
CYAN = lambda s: c(s, "36")

TIER_PAINT = {"low": GREEN, "medium": YELLOW, "high": RED}


def human(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def parse_size(text: str) -> int:
    text = text.strip().upper()
    mult = 1
    if text and text[-1] in "BKMGT":
        mult = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[text[-1]]
        text = text[:-1]
    return int(float(text or 0) * mult)


def age_days(mtime: float) -> float:
    return max(0.0, (time.time() - mtime) / 86400) if mtime else 0.0


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def path_is_protected(path: Path) -> str:
    """Return a reason string if this path must never be touched."""
    parts = path.parts
    for part in parts:
        if part in FORBIDDEN_PARTS:
            return f"protected component: {part}"
        if _looks_like_cloud_dir(part):
            return f"cloud-sync folder: {part}"
    if len(parts) < 3:
        return "path too shallow"
    if path in (HOME, Path("/")):
        return "refusing home/root"
    return ""


def on_disk_size(st) -> int:
    """Bytes this file actually occupies, not its logical length.

    `st_blocks` is authoritative wherever it exists and must NOT fall back to
    `st_size` when it reads zero. Dataless placeholders (the iCloud Drive, Google
    Drive and OneDrive mounts under ~/Library/CloudStorage) and sparse files
    legitimately occupy no local blocks while reporting a large size. Counting
    that length invents reclaimable space that deleting cannot recover — it
    inflated one ~/Library measurement from 29.9G to 704G.
    """
    blocks = getattr(st, "st_blocks", None)
    return blocks * 512 if blocks is not None else st.st_size


def _path_key(path: Path) -> str:
    value = os.path.normpath(str(path))
    return os.path.normcase(value) if os.name == "nt" else value


def _is_excluded(path: Path, excluded_paths=()) -> bool:
    candidate = _path_key(path)
    for excluded in excluded_paths:
        boundary = _path_key(Path(excluded))
        try:
            if os.path.commonpath([candidate, boundary]) == boundary:
                return True
        except ValueError:
            continue
    return False


def dir_stats(path: Path, excluded_paths=()) -> tuple[int, float, int]:
    """(bytes on disk, newest mtime, file count). Never follows symlinks."""
    total = 0
    newest = 0.0
    files = 0
    try:
        st = path.lstat()
    except OSError:
        return 0, 0.0, 0
    if not os.path.isdir(path) or path.is_symlink():
        return on_disk_size(st), st.st_mtime, 1
    newest = st.st_mtime
    stack = [str(path)]
    while stack:
        d = stack.pop()
        if _is_excluded(Path(d), excluded_paths):
            continue
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for entry in it:
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if est.st_mtime > newest:
                    newest = est.st_mtime
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                else:
                    total += on_disk_size(est)
                    files += 1
    return total, newest, files


# ---------------------------------------------------------------------------
# candidates
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    path: Path
    rule_id: str
    tier: str
    label: str
    regen: str
    warn: str = ""
    source: str = "static"      # static | project
    expect_name: str = ""
    size: int = 0
    mtime: float = 0.0
    files: int = 0

    def __post_init__(self):
        if not self.expect_name:
            self.expect_name = self.path.name


# ---------------------------------------------------------------------------
# discovery: static rules
# ---------------------------------------------------------------------------

def discover_static(include_system: bool, excluded_paths=()) -> list[Candidate]:
    found: dict[Path, Candidate] = {}
    for rule in STATIC_RULES:
        if not rule.applies_here():
            continue
        if rule.system and not include_system:
            continue
        if rule.glob.startswith("/"):
            base = Path("/")
            pattern = rule.glob.lstrip("/")
        else:
            base = HOME
            pattern = rule.glob
        try:
            matches = sorted(base.glob(pattern)) if any(ch in pattern for ch in "*?[") \
                else ([base / pattern] if (base / pattern).exists() else [])
        except OSError:
            continue
        for match in matches:
            targets = []
            if rule.children:
                try:
                    targets = [p for p in sorted(match.iterdir())]
                except OSError:
                    continue
            else:
                targets = [match]
            for target in targets:
                if _is_excluded(target, excluded_paths):
                    continue
                if not target.exists() and not target.is_symlink():
                    continue
                if target in found:
                    continue  # earlier (more specific) rule wins
                if path_is_protected(target):
                    continue
                found[target] = Candidate(
                    path=target, rule_id=rule.id, tier=rule.tier,
                    label=rule.label, regen=rule.regen, warn=rule.warn,
                    source="static",
                )
    return list(found.values())


# ---------------------------------------------------------------------------
# discovery: project artifacts
# ---------------------------------------------------------------------------

def match_artifact(name: str, siblings: set[str], path: Path) -> ArtifactRule | None:
    for rule in ARTIFACT_RULES.get(name, ()):
        if rule.markers and not any(m in siblings for m in rule.markers):
            continue
        if rule.contains and not all((path / c).exists() for c in rule.contains):
            continue
        return rule
    return None


def git_repo_root(path: Path, cache: dict) -> Path | None:
    cur = path
    while cur != cur.parent:
        if cur in cache:
            return cache[cur]
        if (cur / ".git").exists():
            for p in _walk_up(path, cur):
                cache[p] = cur
            return cur
        cur = cur.parent
    for p in _walk_up(path, None):
        cache[p] = None
    return None


def _walk_up(path: Path, stop: Path | None):
    cur = path
    while cur != cur.parent:
        yield cur
        if stop is not None and cur == stop:
            return
        cur = cur.parent


def _git_path(path: Path) -> str:
    """A path in the spelling git uses.

    `check-ignore --stdin` echoes back the paths it was handed, and git speaks
    forward slashes on every platform. Handing it a Windows path verbatim gets
    back something that no longer matches the key we look it up by, and a miss
    here silently drops a finding - so both ends go through this.
    """
    return str(path).replace("\\", "/") if os.name == "nt" else str(path)


def filter_gitignored(pending: list[tuple[Path, ArtifactRule]]) -> list[tuple[Path, ArtifactRule]]:
    """Keep only paths that git already ignores (proof they are build output)."""
    cache: dict = {}
    by_repo: dict[Path, list[tuple[Path, ArtifactRule]]] = {}
    for path, rule in pending:
        root = git_repo_root(path.parent, cache)
        if root is None:
            continue  # not in a repo -> we cannot prove it is output; skip
        by_repo.setdefault(root, []).append((path, rule))
    kept: list[tuple[Path, ArtifactRule]] = []
    for root, items in by_repo.items():
        payload = "\n".join(_git_path(p) for p, _ in items)
        try:
            res = subprocess.run(
                ["git", "-C", str(root), "check-ignore", "--stdin"],
                input=payload, capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        ignored = {line.strip() for line in res.stdout.splitlines() if line.strip()}
        for path, rule in items:
            if _git_path(path) in ignored:
                kept.append((path, rule))
    return kept


def discover_projects(roots: list[Path], max_depth: int, progress, excluded_paths=()) -> list[Candidate]:
    out: list[Candidate] = []
    pending_git: list[tuple[Path, ArtifactRule]] = []
    seen_dirs = 0

    for root in roots:
        if not root.is_dir():
            continue
        try:
            root_dev = root.stat().st_dev
        except OSError:
            continue
        stack: list[tuple[str, int]] = [(str(root), 0)]
        while stack:
            d, depth = stack.pop()
            if _is_excluded(Path(d), excluded_paths):
                continue
            seen_dirs += 1
            if progress and seen_dirs % 400 == 0:
                progress(f"scanning… {seen_dirs} dirs")
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            siblings = {e.name for e in entries}
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                name = entry.name
                path = Path(entry.path)
                if _is_excluded(path, excluded_paths):
                    continue
                if depth == 0 and name in SKIP_TOP_LEVEL:
                    continue
                if path_is_protected(path):
                    continue
                try:
                    if entry.stat(follow_symlinks=False).st_dev != root_dev:
                        continue  # do not cross volumes
                except OSError:
                    continue

                rule = match_artifact(name, siblings, path)
                if rule:
                    if rule.need_gitignored:
                        pending_git.append((path, rule))
                    else:
                        out.append(Candidate(
                            path=path, rule_id=rule.id, tier=rule.tier,
                            label=rule.label, regen=rule.regen, source="project",
                        ))
                    continue  # never descend into an artifact

                if name.startswith(".") and name not in HIDDEN_ARTIFACTS:
                    continue
                if depth < max_depth:
                    stack.append((entry.path, depth + 1))

    for path, rule in filter_gitignored(pending_git):
        out.append(Candidate(
            path=path, rule_id=rule.id, tier=rule.tier,
            label=rule.label, regen=rule.regen, source="project",
        ))
    return out


# ---------------------------------------------------------------------------
# sizing + dedupe
# ---------------------------------------------------------------------------

def dedupe_nested(cands: list[Candidate]) -> list[Candidate]:
    """Drop candidates contained inside another candidate."""
    # sort by path *components* so a child always immediately follows its parent
    # (plain string sort puts "/a-b" between "/a" and "/a/c")
    cands.sort(key=lambda x: x.path.parts)
    kept: list[Candidate] = []
    for cand in cands:
        if kept and is_within(cand.path, kept[-1].path) and cand.path != kept[-1].path:
            continue
        if kept and cand.path == kept[-1].path:
            continue
        kept.append(cand)
    return kept


def measure(cands: list[Candidate], progress, excluded_paths=()) -> None:
    done = 0
    total = len(cands)

    def work(cand: Candidate):
        nonlocal done
        cand.size, cand.mtime, cand.files = dir_stats(cand.path, excluded_paths)
        done += 1
        if progress and done % 25 == 0:
            progress(f"measuring… {done}/{total}")

    with ThreadPoolExecutor(max_workers=min(16, (os.cpu_count() or 4) * 2)) as pool:
        list(pool.map(work, cands))


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def group_by_rule(cands: list[Candidate]) -> list[dict]:
    groups: dict[str, dict] = {}
    for cand in cands:
        g = groups.setdefault(cand.rule_id, {
            "id": cand.rule_id, "tier": cand.tier, "label": cand.label,
            "regen": cand.regen, "warn": cand.warn, "size": 0, "count": 0,
            "items": [],
        })
        g["size"] += cand.size
        g["count"] += 1
        g["items"].append(cand)
        if cand.warn:
            g["warn"] = cand.warn
    ordered = sorted(groups.values(), key=lambda g: (TIER_RANK[g["tier"]], -g["size"]))
    return ordered


def print_report(cands: list[Candidate], args) -> None:
    if not cands:
        print("Nothing matched the current filters.")
        return

    groups = group_by_rule(cands)
    tier_totals = {t: 0 for t in TIER_ORDER}
    for cand in cands:
        tier_totals[cand.tier] += cand.size

    usage = shutil.disk_usage("/")
    print()
    print(BOLD(f"cachereaper {VERSION}") + DIM(f"   disk: {human(usage.free)} free of {human(usage.total)}"))
    print()

    for tier in TIER_ORDER:
        tgroups = [g for g in groups if g["tier"] == tier]
        if not tgroups:
            continue
        paint = TIER_PAINT[tier]
        head = {
            "low": "LOW RISK      pure caches, regenerate automatically",
            "medium": "MEDIUM RISK   reinstallable, costs you time/bandwidth",
            "high": "HIGH RISK     stateful or expensive - review each one",
        }[tier]
        print(paint(BOLD(head)) + DIM(f"   [{human(tier_totals[tier])}]"))
        print(DIM("  " + "-" * 74))
        for g in tgroups:
            if g["size"] < args.min_size and g["count"] == 1:
                continue
            count = f"x{g['count']}" if g["count"] > 1 else "  "
            print(f"  {human(g['size']):>8}  {count:<5} {BOLD(g['id']):<26} {DIM(g['label'])}")
            if g["warn"]:
                print(f"            {RED('! ' + g['warn'])}")
            if args.verbose:
                items = sorted(g["items"], key=lambda x: -x.size)[: args.top]
                for it in items:
                    disp = str(it.path).replace(str(HOME), "~")
                    print(f"            {DIM(human(it.size).rjust(8))}  {DIM(f'{age_days(it.mtime):.0f}d')}  {disp}")
                if len(g["items"]) > args.top:
                    print(DIM(f"            … and {len(g['items']) - args.top} more (raise --top)"))
            if args.verbose:
                print(DIM(f"            restore: {g['regen']}"))
        print()

    total = sum(tier_totals.values())
    print(BOLD("  reclaimable"))
    for tier in TIER_ORDER:
        if tier_totals[tier]:
            print(f"    {TIER_PAINT[tier](tier):<18} {human(tier_totals[tier]):>9}")
    print(f"    {'total':<9} {human(total):>9}")
    print()
    print(DIM("  next: cachereaper select                     (pick what to remove)"))
    print(DIM("        cachereaper clean --tier low           (safe caches only)"))
    print(DIM("        cachereaper scan -v --top 10           (see paths)"))
    print(DIM("        cachereaper tools                      (safer vendor commands)"))
    print()


# ---------------------------------------------------------------------------
# interactive selection
# ---------------------------------------------------------------------------

MARK = {"all": "[x]", "some": "[~]", "none": "[ ]"}


def _group_state(group: dict, selected: set) -> str:
    hits = sum(1 for it in group["items"] if str(it.path) in selected)
    if hits == 0:
        return "none"
    return "all" if hits == len(group["items"]) else "some"


def _toggle_group(group: dict, selected: set) -> None:
    if _group_state(group, selected) == "all":
        for it in group["items"]:
            selected.discard(str(it.path))
    else:
        for it in group["items"]:
            selected.add(str(it.path))


def _build_rows(groups: list[dict], expanded: set, filt: str) -> list[tuple]:
    rows = []
    for g in groups:
        items = g["items"]
        if filt:
            in_head = filt in g["id"].lower() or filt in g["label"].lower()
            if not in_head:
                items = [i for i in items if filt in str(i.path).lower()]
                if not items:
                    continue
        rows.append(("group", g, None))
        if g["id"] in expanded:
            for it in sorted(items, key=lambda x: -x.size):
                rows.append(("item", g, it))
    return rows


def _preselect(groups: list[dict]) -> set:
    """Low-risk items start selected; medium/high start unselected."""
    return {str(it.path) for g in groups if g["tier"] == "low" for it in g["items"]}


def curses_select(groups: list[dict]):
    import curses

    def run(scr):
        curses.curs_set(0)
        scr.keypad(True)
        color = curses.has_colors()
        if color:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
        tier_attr = {"low": 1, "medium": 2, "high": 3}

        def paint(tier):
            return curses.color_pair(tier_attr[tier]) if color else 0

        def put(y, x, text, attr=0):
            h, w = scr.getmaxyx()
            if 0 <= y < h and x < w:
                try:
                    scr.addnstr(y, x, text, max(0, w - x - 1), attr)
                except curses.error:
                    pass

        selected = _preselect(groups)
        expanded: set = set()
        filt = ""
        cursor = 0
        top = 0
        grand = sum(g["size"] for g in groups)

        while True:
            rows = _build_rows(groups, expanded, filt)
            if not rows:
                rows = [("empty", None, None)]
            cursor = max(0, min(cursor, len(rows) - 1))
            h, w = scr.getmaxyx()
            body = max(1, h - 5)
            if cursor < top:
                top = cursor
            if cursor >= top + body:
                top = cursor - body + 1

            scr.erase()
            chosen = sum(it.size for g in groups for it in g["items"]
                         if str(it.path) in selected)
            head = f" cachereaper — select what to remove "
            put(0, 0, head + " " * max(0, w - len(head)),
                curses.A_REVERSE if color else curses.A_REVERSE)
            put(1, 1, f"selected {human(chosen)} of {human(grand)}"
                      f"   ({len(selected)} paths)"
                      + (f"   filter: {filt}" if filt else ""),
                curses.A_BOLD)

            for idx in range(top, min(len(rows), top + body)):
                y = 2 + idx - top
                kind, g, it = rows[idx]
                sel = curses.A_REVERSE if idx == cursor else 0
                if kind == "empty":
                    put(y, 2, "no matches", sel)
                    continue
                if kind == "group":
                    mark = MARK[_group_state(g, selected)]
                    arrow = "v" if g["id"] in expanded else ">"
                    count = f"x{g['count']}" if g["count"] > 1 else "  "
                    line = (f" {mark} {arrow} {human(g['size']):>8}  {count:<5} "
                            f"{g['id']:<24} {g['label']}")
                    put(y, 0, line + " " * max(0, w - len(line) - 1),
                        paint(g["tier"]) | curses.A_BOLD | sel)
                else:
                    mark = "[x]" if str(it.path) in selected else "[ ]"
                    disp = str(it.path).replace(str(HOME), "~")
                    line = (f"      {mark} {human(it.size):>8}  "
                            f"{age_days(it.mtime):>4.0f}d  {disp}")
                    put(y, 0, line + " " * max(0, w - len(line) - 1), sel)

            put(h - 2, 1, "space toggle   enter expand/collapse   a all   n none   "
                          "1/2/3 tier low/med/high", curses.A_DIM if color else 0)
            put(h - 1, 1, "/ filter   d done (proceed)   q cancel",
                curses.A_DIM if color else 0)
            scr.refresh()

            try:
                key = scr.getch()
            except KeyboardInterrupt:
                return None

            kind, g, it = rows[cursor] if rows[cursor][0] != "empty" else ("empty", None, None)

            if key in (ord("q"), 27):
                return None
            elif key in (ord("d"), ord("D")):
                return [i for gg in groups for i in gg["items"] if str(i.path) in selected]
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor += 1
            elif key in (curses.KEY_UP, ord("k")):
                cursor -= 1
            elif key == curses.KEY_NPAGE:
                cursor += body
            elif key == curses.KEY_PPAGE:
                cursor -= body
            elif key == curses.KEY_HOME:
                cursor = 0
            elif key == curses.KEY_END:
                cursor = len(rows) - 1
            elif key == ord(" "):
                if kind == "group":
                    _toggle_group(g, selected)
                elif kind == "item":
                    key_p = str(it.path)
                    selected.discard(key_p) if key_p in selected else selected.add(key_p)
                cursor += 1
            elif key in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT, curses.KEY_LEFT):
                if kind == "group":
                    expanded.discard(g["id"]) if g["id"] in expanded else expanded.add(g["id"])
                elif kind == "item":
                    expanded.discard(g["id"])
            elif key == ord("a"):
                for gg in groups:
                    for i in gg["items"]:
                        selected.add(str(i.path))
            elif key == ord("n"):
                selected.clear()
            elif key in (ord("1"), ord("2"), ord("3")):
                tier = {ord("1"): "low", ord("2"): "medium", ord("3"): "high"}[key]
                tgroups = [gg for gg in groups if gg["tier"] == tier]
                on = all(_group_state(gg, selected) == "all" for gg in tgroups) if tgroups else False
                for gg in tgroups:
                    for i in gg["items"]:
                        selected.discard(str(i.path)) if on else selected.add(str(i.path))
            elif key == ord("/"):
                curses.echo()
                curses.curs_set(1)
                put(h - 1, 1, " " * (w - 2))
                put(h - 1, 1, "filter: ")
                try:
                    filt = scr.getstr(h - 1, 9, 40).decode().strip().lower()
                except Exception:
                    filt = ""
                curses.noecho()
                curses.curs_set(0)
                cursor = 0
                top = 0
            elif key == curses.KEY_RESIZE:
                continue

    return curses.wrapper(run)


def plain_select(groups: list[dict]):
    """Numbered fallback for non-TTY / no-curses environments."""
    selected = _preselect(groups)
    while True:
        print()
        print(BOLD("  #   tier    size    count  rule"))
        for n, g in enumerate(groups, 1):
            state = MARK[_group_state(g, selected)]
            count = f"x{g['count']}" if g["count"] > 1 else ""
            print(f"  {n:<3} {TIER_PAINT[g['tier']](g['tier'][:3])}  {state} "
                  f"{human(g['size']):>8}  {count:<5} {g['id']:<24} {DIM(g['label'])}")
        chosen = sum(it.size for g in groups for it in g["items"] if str(it.path) in selected)
        print(f"\n  selected: {BOLD(human(chosen))} ({len(selected)} paths)")
        print(DIM("  toggle: numbers/ranges (1,3,5-8) | low | medium | high | all | none"))
        print(DIM("  then:   d = delete selected, q = cancel"))
        try:
            raw = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("q", "quit", "exit"):
            return None
        if raw in ("d", "done", "delete", ""):
            return [i for g in groups for i in g["items"] if str(i.path) in selected]
        if raw == "all":
            selected = {str(i.path) for g in groups for i in g["items"]}
            continue
        if raw == "none":
            selected.clear()
            continue
        if raw in TIER_ORDER:
            tgroups = [g for g in groups if g["tier"] == raw]
            on = all(_group_state(g, selected) == "all" for g in tgroups) if tgroups else False
            for g in tgroups:
                for i in g["items"]:
                    selected.discard(str(i.path)) if on else selected.add(str(i.path))
            continue
        picked = set()
        for chunk in raw.replace(" ", ",").split(","):
            if not chunk:
                continue
            if "-" in chunk:
                a, _, b = chunk.partition("-")
                if a.isdigit() and b.isdigit():
                    picked.update(range(int(a), int(b) + 1))
            elif chunk.isdigit():
                picked.add(int(chunk))
        if not picked:
            print(YELLOW("  unrecognised input"))
            continue
        for n in picked:
            if 1 <= n <= len(groups):
                _toggle_group(groups[n - 1], selected)


def choose(cands: list[Candidate], args):
    groups = group_by_rule(cands)
    if args.plain or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return plain_select(groups)
    try:
        import curses  # noqa: F401
    except Exception:
        return plain_select(groups)
    try:
        return curses_select(groups)
    except Exception as exc:
        print(YELLOW(f"  interactive UI unavailable ({exc}); falling back"))
        return plain_select(groups)


# ---------------------------------------------------------------------------
# deletion
# ---------------------------------------------------------------------------

def validate_for_delete(cand: Candidate, allowed_roots: list[Path]) -> str:
    p = cand.path
    if not p.is_absolute():
        return "not absolute"
    reason = path_is_protected(p)
    if reason:
        return reason
    if p.name != cand.expect_name:
        return "name changed since scan"
    if not any(is_within(p, r) for r in allowed_roots):
        return "outside allowed roots"
    if p.is_symlink():
        return "symlink"
    if not p.exists():
        return "already gone"
    if cand.tier == "high" and not os.access(p, os.W_OK):
        return "not writable (needs sudo?)"
    return ""


def allowed_roots_for(args) -> list[Path]:
    """Deletion is confined to $HOME plus any roots the user explicitly scanned."""
    roots = [HOME]
    for r in (getattr(args, "roots", None) or []):
        p = _absolute_lexical(r)
        if p != Path("/") and len(p.parts) >= 2:
            roots.append(p)
    # geteuid is unix-only, and every --system rule is macOS-only anyway, so
    # asking on Windows is both impossible and pointless.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root and getattr(args, "system", False):
        roots += [Path("/Library/Caches"), Path("/private/var/folders")]
    return roots


_RECEIPT_COUNTER = 0


def _free_space(path: Path) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def delete(cands: list[Candidate], dry_run: bool, allowed: list[Path]) -> tuple[int, int, list[str]]:
    global _RECEIPT_COUNTER
    freed = 0
    removed = 0
    errors: list[str] = []
    receipt_skipped = 0
    root = HOME
    if cands:
        containing = [path for path in allowed if is_within(cands[0].path, path)]
        if containing:
            root = max(containing, key=lambda path: len(path.parts))
    log = None
    logfile = None
    free_before = None
    receipt_id = None
    if not dry_run:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            stamp = int(time.time() * 1000)
            receipt_id = f"{stamp}-{os.getpid()}-{_RECEIPT_COUNTER}"
            _RECEIPT_COUNTER += 1
            logfile = LOG_DIR / f"receipt-{receipt_id}.jsonl"
            free_before = _free_space(root)
            log = logfile.open("x", encoding="utf-8")
            log.write(json.dumps({
                "schema": 1, "kind": "header", "receipt_id": receipt_id,
                "started_at": stamp, "root": str(root),
                "estimated_bytes": sum(cand.size for cand in cands),
                "free_before": free_before,
            }) + "\n")
            log.flush()
            os.fsync(log.fileno())
        except OSError as exc:
            if log:
                log.close()
            return 0, 0, [f"deletion aborted: could not create receipt: {exc}"]

    def audit(cand, status, reason=""):
        if not log:
            return
        log.write(json.dumps({
            "schema": 1, "kind": "item", "path": str(cand.path),
            "rule": cand.rule_id, "tier": cand.tier, "label": cand.label,
            "regen": cand.regen, "estimated_bytes": cand.size,
            "status": status, "reason": reason,
        }) + "\n")
        log.flush()

    complete = True
    try:
        for cand in cands:
            why = validate_for_delete(cand, allowed)
            if why:
                receipt_skipped += 1
                if why not in ("already gone",):
                    errors.append(f"skip {cand.path}: {why}")
                try:
                    audit(cand, "skipped", why)
                except OSError as exc:
                    errors.append(f"audit append failed; stopped: {exc}")
                    complete = False
                    break
                continue
            if dry_run:
                freed += cand.size
                removed += 1
                print(DIM(f"  would remove  {human(cand.size):>8}  {str(cand.path).replace(str(HOME), '~')}"))
                continue
            try:
                if cand.path.is_dir():
                    shutil.rmtree(cand.path, ignore_errors=False)
                else:
                    cand.path.unlink()
            except OSError as exc:
                receipt_skipped += 1
                errors.append(f"failed {cand.path}: {exc}")
                try:
                    audit(cand, "skipped", str(exc))
                except OSError as audit_exc:
                    errors.append(f"audit append failed; stopped: {audit_exc}")
                    complete = False
                    break
                continue
            freed += cand.size
            removed += 1
            try:
                audit(cand, "removed")
            except OSError as exc:
                errors.append(f"audit append failed after deletion; stopped: {exc}")
                complete = False
                break
            print(f"  {GREEN('removed')}  {human(cand.size):>8}  {str(cand.path).replace(str(HOME), '~')}")
    finally:
        if log:
            try:
                free_after = _free_space(root)
                log.write(json.dumps({
                    "schema": 1, "kind": "summary", "finished_at": int(time.time() * 1000),
                    "removed_count": removed, "skipped_count": receipt_skipped,
                    "estimated_removed_bytes": freed, "free_after": free_after,
                    "signed_free_space_change": (free_after - free_before)
                    if free_after is not None and free_before is not None else None,
                    "complete": complete,
                }) + "\n")
                log.flush()
                os.fsync(log.fileno())
            except OSError as exc:
                errors.append(f"could not finish receipt: {exc}")
            log.close()
            print(DIM(f"\n  log: {logfile}"))
    return freed, removed, errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_saved_config() -> tuple[dict, str | None]:
    path = LOG_DIR / "config.json"
    if not path.exists():
        return {}, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("top level is not an object")
        return value, None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {}, f"warning: ignoring malformed config {path}: {exc}"


def _absolute_lexical(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(value))))


def apply_saved_scan_settings(args) -> None:
    args.saved_excluded_paths = []
    args.saved_excluded_rules = []
    ignoring = getattr(args, "ignore_saved_exclusions", False)
    if ignoring and not getattr(args, "profile", None):
        return

    config, warning = load_saved_config()
    if warning:
        print(warning, file=sys.stderr)
    if not ignoring:
        args.saved_excluded_paths.extend(
            _absolute_lexical(path) for path in config.get("global_excluded_paths", [])
            if isinstance(path, str)
        )
        args.saved_excluded_rules.extend(
            rule for rule in config.get("global_excluded_rules", []) if isinstance(rule, str)
        )

    wanted = getattr(args, "profile", None)
    if not wanted:
        return
    profiles = config.get("profiles", [])
    profile = next((item for item in profiles if isinstance(item, dict) and
                    (item.get("id") == wanted or
                     str(item.get("name", "")).casefold() == wanted.casefold())), None)
    if profile is None:
        raise ValueError(f"profile not found: {wanted}")
    root = profile.get("root")
    if not isinstance(root, str) or not Path(root).is_absolute():
        raise ValueError(f"profile {wanted!r} has an invalid root")
    args.roots = [str(_absolute_lexical(root))]
    if not ignoring:
        args.saved_excluded_paths.extend(
            _absolute_lexical(path) for path in profile.get("excluded_paths", [])
            if isinstance(path, str)
        )
        args.saved_excluded_rules.extend(
            rule for rule in profile.get("excluded_rules", []) if isinstance(rule, str)
        )

def collect(args) -> list[Candidate]:
    def progress(msg):
        if not args.json and sys.stderr.isatty():
            print(f"\r\033[K{DIM(msg)}", end="", file=sys.stderr, flush=True)

    excluded_paths = list(getattr(args, "saved_excluded_paths", []))
    excluded_paths += [_absolute_lexical(path) for path in (getattr(args, "exclude_path", None) or [])]
    cands: list[Candidate] = []
    if not args.no_static:
        cands += discover_static(args.system, excluded_paths)
    if not args.no_projects:
        roots = [_absolute_lexical(r) for r in args.roots] if args.roots else [HOME]
        cands += discover_projects(roots, args.max_depth, progress, excluded_paths)

    cands = dedupe_nested(cands)

    if args.only:
        wanted = set(args.only)
        cands = [c_ for c_ in cands if c_.rule_id in wanted]
    unwanted = set(getattr(args, "saved_excluded_rules", []))
    unwanted.update(args.exclude or [])
    if unwanted:
        cands = [c_ for c_ in cands if c_.rule_id not in unwanted]
    cands = [c_ for c_ in cands if TIER_RANK[c_.tier] <= TIER_RANK[args.tier]]

    measure(cands, progress, excluded_paths)
    if sys.stderr.isatty() and not args.json:
        print("\r\033[K", end="", file=sys.stderr, flush=True)

    cands = [c_ for c_ in cands if c_.size >= args.min_size]
    if args.stale_days:
        cutoff = args.stale_days
        cands = [c_ for c_ in cands if age_days(c_.mtime) >= cutoff]
    cands.sort(key=lambda x: (TIER_RANK[x.tier], -x.size))
    return cands


def cmd_scan(args) -> int:
    cands = collect(args)
    if args.json:
        print(json.dumps([{
            "path": str(x.path), "rule": x.rule_id, "tier": x.tier,
            "bytes": x.size, "files": x.files, "age_days": round(age_days(x.mtime), 1),
            "label": x.label, "regen": x.regen, "source": x.source,
        } for x in cands], indent=2))
        return 0
    print_report(cands, args)
    return 0


def cmd_clean(args) -> int:
    cands = collect(args)
    if not cands:
        print("Nothing to clean with the current filters.")
        return 0

    if args.interactive:
        picked = choose(cands, args)
        if picked is None:
            print("aborted")
            return 1
        if not picked:
            print("nothing selected")
            return 0
        cands = picked
        print()
        for g in group_by_rule(cands):
            count = f"x{g['count']}" if g["count"] > 1 else "  "
            print(f"  {TIER_PAINT[g['tier']](g['tier'][:3])}  {human(g['size']):>8}  "
                  f"{count:<5} {BOLD(g['id']):<26} {DIM(g['label'])}")
        print()
    else:
        print_report(cands, args)

    total = sum(x.size for x in cands)

    if args.dry_run:
        print(BOLD("DRY RUN - nothing will be deleted\n"))
        freed, removed, errors = delete(cands, dry_run=True, allowed=allowed_roots_for(args))
        print(f"\n  would free {BOLD(human(freed))} across {removed} paths")
        for e in errors[:10]:
            print(DIM("  " + e))
        return 0

    high = [x for x in cands if x.tier == "high"]
    print(BOLD(f"About to delete {len(cands)} paths, freeing ~{human(total)}."))
    if high:
        print(RED(f"{len(high)} of them are HIGH RISK ({human(sum(x.size for x in high))}):"))
        for x in sorted(high, key=lambda y: -y.size)[:10]:
            print(RED(f"    {human(x.size):>8}  {str(x.path).replace(str(HOME), '~')}"))

    if not args.yes:
        if high:
            phrase = "delete high risk"
            print(f"\nType {BOLD(phrase)} to proceed, anything else aborts.")
            try:
                answer = input("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\naborted")
                return 1
            if answer != phrase:
                print("aborted")
                return 1
        else:
            try:
                answer = input("\nProceed? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\naborted")
                return 1
            if answer not in ("y", "yes"):
                print("aborted")
                return 1

    print()
    freed, removed, errors = delete(cands, dry_run=False, allowed=allowed_roots_for(args))
    usage = shutil.disk_usage("/")
    print()
    print(BOLD(f"  freed {human(freed)} across {removed} paths"))
    print(DIM(f"  disk now: {human(usage.free)} free of {human(usage.total)}"))
    if errors:
        print(YELLOW(f"\n  {len(errors)} skipped/failed:"))
        for e in errors[:20]:
            print(DIM("    " + e))
    return 0


def rules_document() -> dict:
    """The rule tables as plain data.

    This Python source stays the single definition of the rules; the GUI embeds
    a generated copy of this document so both halves cannot disagree about what
    is safe to delete. `gui/rules.generated.json` is checked against this in CI.
    """
    return {
        "schema": 2,
        "version": VERSION,
        "tiers": list(TIER_ORDER),
        "forbidden_parts": sorted(FORBIDDEN_PARTS),
        "cloud_dir_hints": list(CLOUD_DIR_HINTS),
        "skip_top_level": sorted(SKIP_TOP_LEVEL),
        "static": [
            {
                "id": r.id, "tier": r.tier, "glob": r.glob, "label": r.label,
                "regen": r.regen, "children": r.children, "warn": r.warn,
                "system": r.system, "os": r.os,
            }
            for r in STATIC_RULES
        ],
        "artifacts": [
            {
                "dir_name": name, "id": r.id, "tier": r.tier, "label": r.label,
                "regen": r.regen, "markers": list(r.markers),
                "contains": list(r.contains), "need_gitignored": r.need_gitignored,
            }
            for name, rules in sorted(ARTIFACT_RULES.items())
            for r in rules
        ],
    }


def cmd_dump_rules(args) -> int:
    print(json.dumps(rules_document(), indent=2, sort_keys=False))
    return 0


def cmd_tools(args) -> int:
    print()
    print(BOLD("Vendor commands that are safer than rm -rf"))
    print(DIM("  these clean in-place and keep the tool working\n"))
    width = max(len(t) for t, _, _ in TOOL_COMMANDS)
    for tool, cmd, note in TOOL_COMMANDS:
        line = f"  {CYAN(tool.ljust(width))}  {cmd}"
        print(line)
        if note:
            print(DIM(f"  {' ' * width}  {note}"))
    print()
    # The rules for this machine only. Listing the Windows table on a Mac would
    # pad it out with three dozen rules that can never fire here.
    print(BOLD(f"Rules cachereaper knows about ({PLATFORM})"))
    for rule in STATIC_RULES:
        if not rule.applies_here():
            continue
        print(f"  {TIER_PAINT[rule.tier](rule.tier[:3]):<4} {rule.id:<24} {DIM(rule.label)}")
    for name, rules in sorted(ARTIFACT_RULES.items()):
        for rule in rules:
            gate = " (git-ignored only)" if rule.need_gitignored else ""
            print(f"  {TIER_PAINT[rule.tier](rule.tier[:3]):<4} {rule.id:<24} {DIM(rule.label + gate)}")
    print()
    return 0


# ---------------------------------------------------------------------------
# updates
# ---------------------------------------------------------------------------
#
# Only ever when asked. The desktop app looks on launch because it has a window
# to put the answer in and a switch to turn it off with; a command-line tool that
# reached the network every time you asked it about your own disk would be
# something else, so `update` is a subcommand and nothing else calls it.

RELEASES = f"https://github.com/{REPO}/releases"
SOURCE_URL = f"https://raw.githubusercontent.com/{REPO}/{{tag}}/cachereaper.py"


def version_tuple(text: str):
    """`"1.10.0"` sorts after `"1.9.0"`, which is the whole point of not
    comparing these as strings. A pre-release suffix is dropped rather than
    ranked: `1.5.0-rc1` and `1.5.0` compare equal here, so an rc never reports
    itself as behind the release it precedes."""
    core = text.strip().lstrip("v").split("-")[0].split("+")[0]
    parts = []
    for piece in core.split("."):
        digits = "".join(c for c in piece if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def latest_tag(timeout: float = 10.0) -> str:
    """The newest release tag, read out of where /releases/latest redirects to.

    Deliberately not the JSON API: that is rate-limited per IP, shares its
    budget with every other unauthenticated caller behind the same address, and
    starts refusing at exactly the moment a lot of people are updating. The
    redirect has no such limit and carries the one fact needed.
    """
    import urllib.request

    request = urllib.request.Request(
        f"{RELEASES}/latest",
        headers={"User-Agent": f"cachereaper/{VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        final = response.geturl()
    tag = final.rstrip("/").rsplit("/", 1)[-1]
    if not tag.startswith("v"):
        raise RuntimeError(f"unexpected release URL: {final}")
    return tag


def fetch_source(tag: str, timeout: float = 30.0) -> str:
    import urllib.request

    request = urllib.request.Request(
        SOURCE_URL.format(tag=tag),
        headers={"User-Agent": f"cachereaper/{VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def check_downloaded(source: str, tag: str) -> None:
    """Refuse anything that is not the file we asked for.

    There is no signature here — this is the same trust as `git pull` on the
    repository, over HTTPS — so what these checks are actually defending against
    is the ordinary accident: a truncated download, a proxy's error page, a tag
    that moved. Each one would otherwise be written over a working program.
    """
    if not source.startswith("#!"):
        raise RuntimeError("that download is not a script")
    if f'VERSION = "{tag.lstrip("v")}"' not in source:
        raise RuntimeError(f"the download does not call itself {tag.lstrip('v')}")
    if "def main(" not in source or len(source) < 20_000:
        raise RuntimeError("the download is incomplete")
    compile(source, "cachereaper.py", "exec")  # SyntaxError if it is mangled


def replace_self(source: str, target: Path) -> None:
    """Write beside the running file and rename over it.

    The rename is atomic, so an interrupted update leaves the old program intact
    rather than half of the new one. It also means the currently running process
    is unaffected: it is already loaded, and Python does not re-read the file.
    """
    scratch = target.parent / f"{target.name}.new"
    scratch.write_text(source, encoding="utf-8")
    scratch.chmod(target.stat().st_mode & 0o7777)
    os.replace(scratch, target)


def cmd_update(args) -> int:
    target = Path(__file__).resolve()

    print()
    print(f"  you have    {BOLD(VERSION)}")
    try:
        tag = latest_tag()
    except Exception as exc:  # noqa: BLE001 - any network failure reads the same
        print(f"  {YELLOW('could not reach the release page')}  {DIM(str(exc))}")
        print(f"  {DIM(RELEASES)}\n")
        return 1

    newest = tag.lstrip("v")
    print(f"  newest is   {BOLD(newest)}")
    print()

    if version_tuple(newest) <= version_tuple(VERSION):
        print(f"  {GREEN('nothing to do')} — this is the newest release\n")
        return 0

    print(f"  {CYAN(f'{newest} is out')}  {DIM(f'{RELEASES}/tag/{tag}')}")

    if not args.install:
        print(f"\n  install it:  {BOLD('cachereaper update --install')}")
        print(f"  {DIM('or, if you run it from a clone: git pull')}\n")
        return 0

    # A pip install owns its own files, and writing into site-packages behind
    # pip's back leaves it reporting a version that is no longer there.
    if "site-packages" in target.parts or "dist-packages" in target.parts:
        print(f"\n  {YELLOW('this copy was installed by pip')} — update it the same way:")
        print(f"  {BOLD('pip install --upgrade cachereaper')}\n")
        return 1
    if not os.access(target, os.W_OK):
        print(f"\n  {YELLOW('cannot write')} {target}")
        print(f"  {DIM('re-run where you can write it, or reinstall over it')}\n")
        return 1

    print(f"  downloading {DIM(SOURCE_URL.format(tag=tag))}")
    try:
        source = fetch_source(tag)
        check_downloaded(source, tag)
        replace_self(source, target)
    except Exception as exc:  # noqa: BLE001
        print(f"\n  {YELLOW('update failed')}  {exc}")
        print(f"  {DIM('nothing was changed — ' + str(target) + ' is untouched')}\n")
        return 1

    print(f"\n  {GREEN('updated')}  {target} is now {newest}")
    print(f"  {DIM('this process is still running the old one — start it again')}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cachereaper",
        description="Find and reclaim disk space from caches and build artifacts.",
        epilog="Dry-run by default. `clean` always asks before deleting.",
    )
    parser.add_argument("--version", action="version", version=f"cachereaper {VERSION}")
    sub = parser.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--tier", choices=TIER_ORDER, default="low",
                       help="highest risk tier to include (default: low)")
        p.add_argument("--stale-days", type=float, default=0,
                       help="only include items untouched for N days")
        p.add_argument("--min-size", type=parse_size, default="0",
                       help="ignore items smaller than this, e.g. 10M (default 0)")
        p.add_argument("--only", nargs="+", metavar="RULE", help="only these rule ids")
        p.add_argument("--exclude", nargs="+", metavar="RULE", help="skip these rule ids")
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("--roots", nargs="+", metavar="DIR",
                           help="directories to scan for project artifacts (default: $HOME)")
        scope.add_argument("--profile", metavar="NAME_OR_ID",
                           help="scan the root and exclusions from a saved profile")
        p.add_argument("--exclude-path", nargs="+", metavar="PATH",
                       help="additional paths not to traverse for this scan")
        p.add_argument("--ignore-saved-exclusions", action="store_true",
                       help="ignore global saved exclusions for a reproducible scan")
        p.add_argument("--max-depth", type=int, default=10, help="project scan depth (default 10)")
        p.add_argument("--system", action="store_true",
                       help="also scan /Library/Caches and /private/var/folders (needs sudo to delete)")
        p.add_argument("--no-projects", action="store_true", help="skip the project artifact scan")
        p.add_argument("--no-static", action="store_true", help="skip known cache locations")
        p.add_argument("--top", type=int, default=8, help="paths shown per rule with -v")
        p.add_argument("-v", "--verbose", action="store_true", help="show individual paths")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    p_scan = sub.add_parser("scan", help="report what could be reclaimed (default)")
    common(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    def clean_flags(p, interactive_default):
        p.add_argument("--yes", action="store_true", help="skip the y/N prompt (high tier still prompts)")
        p.add_argument("--dry-run", action="store_true", help="list exactly what would be removed")
        p.add_argument("--plain", action="store_true", help="numbered picker instead of the full-screen UI")
        p.add_argument("-i", "--interactive", action="store_true", default=interactive_default,
                       help="pick what to remove after the scan")
        if interactive_default:
            p.add_argument("--no-interactive", dest="interactive", action="store_false",
                           help="delete everything matching the filters instead of picking")

    p_clean = sub.add_parser("clean", help="delete after confirmation")
    common(p_clean)
    clean_flags(p_clean, interactive_default=False)
    p_clean.set_defaults(func=cmd_clean)

    p_select = sub.add_parser("select", help="scan, then pick what to remove (interactive)")
    common(p_select)
    clean_flags(p_select, interactive_default=True)
    # `select` shows every tier by default — nothing is preselected above low
    p_select.set_defaults(func=cmd_clean, tier="high")

    p_tools = sub.add_parser("tools", help="safer vendor commands + full rule list")
    p_tools.set_defaults(func=cmd_tools)

    p_dump = sub.add_parser("dump-rules", help="print the rule tables as JSON (consumed by the GUI)")
    p_dump.set_defaults(func=cmd_dump_rules)

    p_update = sub.add_parser("update", help="check for a newer release (the only command that uses the network)")
    p_update.add_argument("--install", action="store_true",
                          help="download it and replace this file")
    p_update.set_defaults(func=cmd_update)

    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--dump-rules":
        argv[0] = "dump-rules"
    if not argv or (argv[0].startswith("-") and argv[0] not in ("--version", "-h", "--help")):
        argv = ["scan"] + argv
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        args = parser.parse_args(["scan"])
    if isinstance(getattr(args, "min_size", 0), str):
        args.min_size = parse_size(args.min_size)
    try:
        if hasattr(args, "roots"):
            apply_saved_scan_settings(args)
        return args.func(args)
    except ValueError as exc:
        print(f"cachereaper: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
