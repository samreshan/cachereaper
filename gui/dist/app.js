// cachereaper treemap.
//
// Runs in two modes:
//   * inside Tauri  -> talks to the Rust core over IPC
//   * plain browser -> loads snapshot.json, produced by
//                      `cargo run --release --bin snapshot -- tree ~ gui/dist/snapshot.json`
// The second mode is what makes the UI developable and screenshot-testable
// without building the desktop shell.

import { squarify, human } from "./treemap.js";
import { ageDays, filterSortFindings, visibleBatch } from "./findings.js";
import { diagnostics, healthWarnings } from "./health.js";
import { cancelViewState, isCurrentScanEvent } from "./lifecycle.js";
import { exclusionSections, referenceRootFor } from "./profiles.js";
import {
  advancedMetrics,
  analysisMetrics,
  formatDuration,
  MODE_DETAILS,
  normalizeMode,
  offloadSummary,
  ownershipStateLabel,
  visibleFileRows,
} from "./insights.js";
import { expiryPresentation } from "./quarantine.js";
import { clauseLabel, planSummary, sortedInsights, targetBytes } from "./planner.js";

// Bigger minimum than feels necessary, on purpose. At 5px the map rendered
// ~15,000 cells and read as speckle; at 10 it renders a few thousand legible
// blocks. You cannot click a 2px rectangle anyway.
const MIN_CELL = 10;
const MAX_DEPTH = 10;
// No gutter: blocks butt against each other and the hairline edge drawn in
// paintLeaf is the only separator. A gutter is applied once per level of
// nesting on the way down, so at 1px a block six levels deep had been inset six
// times — the channels that opened up read as empty space rather than as
// structure, and cost area that the blocks themselves should have had.
const GAP = 0;

const canvas = document.getElementById("map");
const ctx = canvas.getContext("2d", { alpha: false });
const tooltip = document.getElementById("tooltip");
const statusEl = document.getElementById("status");
const marqueeEl = document.getElementById("marquee");

const state = {
  nodes: [],
  rootPath: "",
  stats: null,
  current: 0,
  cells: [], // drawn rectangles, for hit testing
  drawnUnder: new Map(), // node -> how many drawn leaves live under it
  selected: new Set(), // node indices
  colourMode: "tier",
  mode: "explore", // explore | select
  hover: -1,
  drag: null,
  findings: [],
  payload: null,
  activeProfileId: null,
  scanMode: "cache",
  view: "map",
  listPages: 1,
};

const home = document.getElementById("home");
const homeStatus = document.getElementById("home-status");

function showHome(message = null) {
  onboarding.hidden = true;
  home.hidden = false;
  document.body.classList.add("at-home");
  homeStatus.hidden = !message;
  homeStatus.textContent = message || "";
  setStatus(null);
}

function hideHome() {
  home.hidden = true;
  document.body.classList.remove("at-home");
}

function setScanMode(mode) {
  state.scanMode = normalizeMode(mode);
  document.getElementById("scan-mode").value = state.scanMode;
  for (const card of document.querySelectorAll("[data-scan-mode]")) {
    const on = card.dataset.scanMode === state.scanMode;
    card.classList.toggle("on", on);
    card.setAttribute("aria-checked", String(on));
  }
}

for (const card of document.querySelectorAll("[data-scan-mode]")) {
  card.onclick = () => setScanMode(card.dataset.scanMode);
}

document.getElementById("scan-mode").onchange = async (event) => {
  const changed = normalizeMode(event.target.value);
  if (changed === state.scanMode) return;
  setScanMode(changed);
  if (state.nodes.length && home.hidden && !scanning) {
    await runScan(state.rootPath);
  }
};

// Timestamp rather than a boolean: a drag is normally followed by a click, but
// not always. A sticky flag would sit there and swallow the next real click.
let lastDragEnd = 0;

// h, s, l components. Risk tiers stay saturated so they carry the eye; anything
// the rules did not claim is deliberately drained of colour so it recedes. The
// map should answer "what can I delete" at a glance, not "what is on my disk".
// High risk is the brand red itself — hsl(359 83% 52%) is #ea1d1f, the reaper's
// cloak — pulled back to 74% saturation so it does not vibrate against the
// amber sitting next to it on the map.
const TIER_HSL = {
  low: [148, 46, 44],
  medium: [40, 68, 48],
  high: [359, 74, 51],
};

const isDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

// Requires `withGlobalTauri` in tauri.conf.json. Without it this is false inside
// the packaged app too, and the UI silently falls back to a snapshot file that
// only exists during browser development — which looks like a working app
// showing stale data. Do not remove that config flag.
const inTauri = typeof window !== "undefined" && !!window.__TAURI__;

// Bound once rather than per scan: `listen` registers a new handler each call,
// so re-binding on every rescan would multiply the progress messages.
let progressBound = false;
let activeScanId = null;

async function load(request) {
  if (inTauri) {
    const { invoke } = window.__TAURI__.core;
    if (!progressBound) {
      const { listen } = window.__TAURI__.event;
      await listen("scan-progress", (e) => {
        const { phase = "walking", files, reclaimable_bytes } = e.payload;
        if (!isCurrentScanEvent(activeScanId, e.payload)) return;
        setStatus(`${phase}… ${files.toLocaleString()} files, ${human(reclaimable_bytes)}`);
        setScanProgress(files, reclaimable_bytes, phase);
      });
      await listen("scan-root-changed", (e) => {
        if (!state.payload || e.payload?.root !== state.rootPath) return;
        document.getElementById("change-notice").hidden = false;
        setStatus("Files changed — snapshot refresh recommended");
      });
      progressBound = true;
    }
    return invoke("scan_request", { request });
  }
  const res = await fetch("snapshot.json");
  if (!res.ok) {
    throw new Error(
      "no snapshot.json — in the browser the map reads a pre-built scan. Run ./gui/dev.sh"
    );
  }
  return res.json();
}

/**
 * Stand-in for the commands behind the onboarding journey, for browser mode.
 *
 * Three gates in three different states, because the states are the whole
 * design and styling them needs all of them on screen at once. Mutable so a
 * click in the browser still moves something.
 *
 * Unreachable inside the packaged app, for the same reason and by the same flag
 * as the snapshot fallback above: if `withGlobalTauri` is ever dropped from
 * tauri.conf.json this would answer instead of the Rust, and the app would show
 * a permissions screen made of nothing.
 */
function browserStub() {
  const gates = [
    { id: "desktop", label: "Desktop", path: "/Users/you/Desktop", state: "granted" },
    { id: "documents", label: "Documents", path: "/Users/you/Documents", state: "unknown" },
    { id: "downloads", label: "Downloads", path: "/Users/you/Downloads", state: "denied" },
  ];
  const find = (id) => gates.find((g) => g.id === id);
  const settle = (id, state) => {
    find(id).state = state;
    return { ...find(id) };
  };
  // Add ?update to the dev URL to work on the update card without cutting a
  // release to have something to be behind.
  const pretendBehind = new URLSearchParams(location.search).has("update");
  const pretendSupport = new URLSearchParams(location.search).has("support");
  let nextSupportAt = pretendSupport ? 0 : Math.floor(Date.now() / 1000) + 86_400;
  let supportDisabled = false;
  let retentionDays = 30;
  const profiles = [];
  const referenceRoots = [];
  return {
    config_get: async () => ({
      seen_onboarding: false,
      access: {},
      auto_update: true,
      support_prompt_at: null,
      support_prompt_disabled: false,
      quarantine_retention_days: retentionDays,
      global_excluded_paths: [],
      global_excluded_rules: [],
      reference_roots: [...referenceRoots],
      profiles: profiles.map((profile) => ({ ...profile })),
      last_profile_id: null,
    }),
    access_status: async () => gates.map((g) => ({ ...g })),
    full_disk_status: async () => "denied",
    request_access: async ({ id }) => settle(id, "granted"),
    revoke_access: async ({ id }) => settle(id, "unknown"),
    open_privacy_settings: async () => {},
    set_seen_onboarding: async () => {},
    reveal: async () => {},
    app_version: async () => "2.1.0-dev",
    set_auto_update: async () => {},
    update_check: async () =>
      pretendBehind
        ? { version: "9.9.9", current: "2.1.0-dev", notes: "A pretend release, for working on this card." }
        : null,
    update_install: async () => {
      throw new Error("installing an update needs the desktop app");
    },
    support_prompt_status: async () => ({
      show: !supportDisabled && Math.floor(Date.now() / 1000) >= nextSupportAt,
      next_at: supportDisabled ? null : nextSupportAt,
    }),
    support_prompt_later: async () => {
      nextSupportAt = Math.floor(Date.now() / 1000) + 86_400;
      return { show: false, next_at: nextSupportAt };
    },
    support_prompt_never: async () => {
      supportDisabled = true;
    },
    open_support_page: async () => {},
    profile_list: async () => [],
    rule_ids: async () => [],
    profile_create: async ({ name, root }) => {
      const profile = { id: `browser-${Date.now()}`, name, root, excluded_paths: [], excluded_rules: [] };
      profiles.push(profile); return { ...profile };
    },
    profile_update: async ({ id, name, root }) => {
      const profile = profiles.find((value) => value.id === id); Object.assign(profile, { name, root }); return { ...profile };
    },
    profile_delete: async ({ id }) => { const index = profiles.findIndex((value) => value.id === id); if (index >= 0) profiles.splice(index, 1); return index >= 0; },
    reference_add: async ({ path }) => { if (!referenceRoots.includes(path)) referenceRoots.push(path); return { reference_roots: [...referenceRoots], profiles }; },
    reference_remove: async ({ path }) => { const index = referenceRoots.indexOf(path); if (index >= 0) referenceRoots.splice(index, 1); return { reference_roots: [...referenceRoots], profiles }; },
    history_list: async () => [],
    action_history_list: async () => [],
    snapshot_history: async () => [],
    history_clear: async () => 0,
    quarantine_history: async () => [],
    quarantine_duplicate: async () => { throw new Error("quarantine needs the desktop app"); },
    trash_duplicate: async () => { throw new Error("Trash needs the desktop app"); },
    quarantine_restore: async () => { throw new Error("restore needs the desktop app"); },
    quarantine_expire: async () => { throw new Error("expiry needs the desktop app"); },
    quarantine_retention_set: async ({ days }) => { retentionDays = days; return { quarantine_retention_days: retentionDays, reference_roots: [...referenceRoots], profiles }; },
    insight_query: async () => { throw new Error("The typed query compiler is available in the desktop app"); },
    cleanup_plan: async () => { throw new Error("The deterministic planner is available in the desktop app"); },
    local_ai_status: async () => ({ enabled: false, privacy: "local-only", authority: "presentation-only" }),
    offload_status: async () => ({ compiled: false, configured_providers: [], per_request_consent_required: true, authority: "connector results cannot authorize local deletion" }),
    cancel_scan: async () => true,
  };
}

const stub = inTauri ? null : browserStub();

function call(cmd, args) {
  if (inTauri) return window.__TAURI__.core.invoke(cmd, args);
  const fn = stub[cmd];
  if (!fn) return Promise.reject(new Error(`${cmd} needs the desktop app`));
  return fn(args ?? {});
}

function setStatus(text) {
  if (text === null) {
    statusEl.hidden = true;
    return;
  }
  statusEl.hidden = false;
  statusEl.textContent = text;
}

/**
 * Live counts under the scanning bar.
 *
 * The core only emits every 20,000 files, so a small folder can finish without
 * ever firing one. That is why the curtain opens on "counting…" rather than on
 * "0 files", which would look stuck for the whole of a short scan.
 */
function setScanProgress(files, bytes, phase = "walking") {
  document.getElementById("scan-counts").textContent =
    `${phase} · ${files.toLocaleString()} files · ${human(bytes)}`;
}

// ---------------------------------------------------------------------------
// tree helpers
// ---------------------------------------------------------------------------

const nameOf = (i) => state.nodes[i].n;
const sizeOf = (i) => state.nodes[i].s;
const ruleOf = (i) => state.nodes[i].r || null;

function claimedAncestor(index) {
  let current = index;
  while (current >= 0) {
    if (ruleOf(current)) return current;
    if (current === 0) break;
    current = state.nodes[current].p;
  }
  return null;
}

function pathOf(index) {
  const parts = [];
  let i = index;
  while (i > 0) {
    parts.push(nameOf(i));
    i = state.nodes[i].p;
  }
  parts.reverse();
  return parts.length ? `${state.rootPath}/${parts.join("/")}` : state.rootPath;
}

function ancestry(index) {
  const chain = [];
  let i = index;
  while (i >= 0) {
    chain.push(i);
    if (i === 0) break;
    i = state.nodes[i].p;
  }
  return chain.reverse();
}

/** true when `a` is `b` itself or one of its ancestors */
function covers(a, b) {
  let i = b;
  let hops = 0;
  while (i >= 0 && hops < 128) {
    if (i === a) return true;
    if (i === 0) return false;
    i = state.nodes[i].p;
    hops += 1;
  }
  return false;
}

// ---------------------------------------------------------------------------
// selection
// ---------------------------------------------------------------------------

/**
 * Add a node, keeping the set free of overlaps: selecting a folder drops any
 * already-selected item inside it, and selecting something already covered by a
 * selected ancestor is a no-op. Without this the byte total double-counts.
 */
function addSelection(index) {
  // Whole/All may expose personal files as read-only evidence. Selection in
  // those modes is confined to the nearest deterministic rule finding.
  if (state.scanMode !== "cache") {
    const claimed = claimedAncestor(index);
    if (claimed === null) return;
    index = claimed;
  }
  if (referenceRootFor(pathOf(index), appConfig?.reference_roots)) return;
  for (const existing of [...state.selected]) {
    if (covers(existing, index)) return; // an ancestor already covers it
    if (covers(index, existing)) state.selected.delete(existing);
  }
  state.selected.add(index);
}

function toggleSelection(index) {
  if (state.selected.has(index)) state.selected.delete(index);
  else addSelection(index);
}

/**
 * Roll a set of drawn leaves up to the largest fully-covered folders.
 *
 * Dragging a box across a node_modules paints hundreds of little leaf cells; the
 * user means "that folder", not "these 400 files". When every drawn cell under a
 * folder falls inside the box, the folder replaces them.
 */
function collapseToFolders(leaves) {
  const covered = new Map();
  for (const leaf of leaves) {
    let i = leaf;
    let hops = 0;
    while (i >= 0 && hops < 128) {
      covered.set(i, (covered.get(i) || 0) + 1);
      if (i === state.current || i === 0) break;
      i = state.nodes[i].p;
      hops += 1;
    }
  }

  const out = new Set();
  for (const leaf of leaves) {
    let best = leaf;
    let i = leaf;
    let hops = 0;
    while (i !== state.current && i !== 0 && hops < 128) {
      const parent = state.nodes[i].p;
      if (parent === state.current || parent < 0) break;
      if (covered.get(parent) !== state.drawnUnder.get(parent)) break;
      best = parent;
      i = parent;
      hops += 1;
    }
    out.add(best);
  }
  return out;
}

function selectionStats() {
  let bytes = 0;
  let unclassified = 0;
  let high = 0;
  for (const i of state.selected) {
    bytes += sizeOf(i);
    const tier = state.nodes[i].t;
    if (!ruleOf(i)) unclassified += 1;
    if (tier === "high") high += 1;
  }
  return { bytes, unclassified, high, count: state.selected.size };
}

// ---------------------------------------------------------------------------
// colour
// ---------------------------------------------------------------------------

const EXT_HUE = {
  js: 45, ts: 45, json: 50, py: 210, rs: 20, go: 190, java: 15, c: 280, h: 280,
  png: 320, jpg: 320, jpeg: 320, gif: 320, svg: 330, mp4: 300, mov: 300,
  zip: 100, gz: 100, tar: 100, dmg: 110, pdf: 0, md: 160, txt: 160,
};

/** Base [h,s,l] for a block, before cushion shading. */
function baseHsl(index, depth) {
  const node = state.nodes[index];
  if (state.colourMode === "tier") {
    const tier = inheritedTier(index);
    if (tier) return TIER_HSL[tier];
    // unclassified: near-neutral, low contrast, nesting shown by a slight step
    return isDark()
      ? [220, 7, 22 + Math.min(depth, 7) * 2.0]
      : [220, 9, 84 - Math.min(depth, 7) * 2.4];
  }
  if (state.colourMode === "age") {
    const days = (Date.now() / 1000 - node.m) / 86400;
    return [Math.max(0, 210 - Math.min(days, 365) * 0.575), 42, 46];
  }
  const ext = node.n.includes(".") ? node.n.split(".").pop().toLowerCase() : "";
  const hue = EXT_HUE[ext] ?? hashString(node.n) % 360;
  return [hue, 30, 44];
}

/** Tier of this node or the nearest claimed ancestor, so a cache subtree reads as one colour. */
function inheritedTier(index) {
  let i = index;
  let hops = 0;
  while (i > 0 && hops < 64) {
    if (state.nodes[i].t) return state.nodes[i].t;
    i = state.nodes[i].p;
    hops += 1;
  }
  return state.nodes[0].t || null;
}

function hashString(s) {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

const hsl = ([h, s, l], dl = 0) => `hsl(${h} ${s}% ${Math.max(4, Math.min(96, l + dl))}%)`;

// ---------------------------------------------------------------------------
// render
// ---------------------------------------------------------------------------

/**
 * The canvas's own box, used for both sizing and hit testing so the two can
 * never disagree.
 *
 * This must NOT come from the wrapper: the wrapper has a 1px border, so its
 * rect is offset from the canvas's, and every hit test landed a pixel off —
 * harmless on large blocks, but it missed thin ones entirely.
 *
 * Reading the canvas rect is safe because CSS (`position:absolute; inset:0;
 * width/height:100%`) fully determines its layout; assigning `canvas.width`
 * no longer feeds back into it.
 */
function box() {
  return canvas.getBoundingClientRect();
}

function resize() {
  const dpr = window.devicePixelRatio || 1;
  const rect = box();
  canvas.width = Math.max(1, Math.round(rect.width * dpr));
  canvas.height = Math.max(1, Math.round(rect.height * dpr));
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  draw();
}

function draw() {
  const rect = box();
  state.cells = [];
  state.drawnUnder = new Map();
  ctx.fillStyle = getComputedStyle(document.body).backgroundColor;
  ctx.fillRect(0, 0, rect.width, rect.height);
  if (!state.nodes.length) return;

  drawNode(state.current, { x: 0, y: 0, w: rect.width, h: rect.height }, 0);
  drawSelection();
  drawHover();
}

function drawNode(index, rect, depth) {
  const node = state.nodes[index];
  const children = node.c || [];

  // Children plus one synthetic cell for the bytes held in files directly here,
  // so a folder full of large files is not invisible next to its subfolders.
  const items = children
    .map((c) => ({ value: sizeOf(c), node: c, kind: "child" }))
    .filter((i) => i.value > 0);
  if (node.o > 0) items.push({ value: node.o, node: index, kind: "own" });

  if (!items.length || depth >= MAX_DEPTH) {
    paintLeaf(index, rect, depth);
    return;
  }

  // Anything that would render smaller than a readable block is folded into a
  // single "N smaller" cell. Drawing them individually produced thousands of
  // 2px specks that carried no information but dominated the texture.
  const area = rect.w * rect.h;
  const total = items.reduce((s, i) => s + i.value, 0);
  const floor = MIN_CELL * MIN_CELL * 2.2;
  const big = [];
  let restValue = 0;
  let restCount = 0;
  for (const item of items) {
    if ((item.value / total) * area >= floor) big.push(item);
    else {
      restValue += item.value;
      restCount += 1;
    }
  }
  if (restValue > 0) big.push({ value: restValue, node: index, kind: "rest", count: restCount });

  if (!big.length) {
    paintLeaf(index, rect, depth);
    return;
  }

  for (const cell of squarify(big, rect)) {
    const item = cell.item;
    if (item.kind === "child" && cell.w >= MIN_CELL && cell.h >= MIN_CELL) {
      drawNode(item.node, GAP ? inset(cell) : cell, depth + 1);
    } else {
      const owner = item.kind === "child" ? item.node : index;
      paintLeaf(owner, cell, depth + 1, item.kind === "rest" ? item.count : 0, item.kind);
    }
  }
}

/**
 * Optional gutter, off by default — see GAP.
 *
 * Kept because it is the only knob for loosening the map again, but note it is
 * applied per level of nesting on the way down, so the visible channel is the
 * gutter times the depth, not the gutter.
 */
function inset(cell) {
  const px = Math.min(GAP, cell.w / 4, cell.h / 4);
  return {
    x: cell.x + px,
    y: cell.y + px,
    w: Math.max(0, cell.w - px * 2),
    h: Math.max(0, cell.h - px * 2),
  };
}

function roundRect(x, y, w, h, r) {
  const radius = Math.max(0, Math.min(r, w / 2, h / 2));
  ctx.beginPath();
  if (ctx.roundRect) ctx.roundRect(x, y, w, h, radius);
  else ctx.rect(x, y, w, h);
  return radius;
}

/**
 * `kind` decides how a cell behaves once drawn:
 *   child — a real node; clickable, and counted for marquee collapse
 *   own   — the files sitting directly in this folder; a click means "the
 *           folder", but it is kept out of the coverage maths so that clipping
 *           the strip with a marquee does not select the whole folder
 *   rest  — the "N smaller" aggregate; stands for many siblings at once, so it
 *           is inert: neither clickable nor counted
 */
function paintLeaf(index, rect, depth, restCount = 0, kind = "child") {
  const base = baseHsl(index, depth);

  // Flat fill and a hairline edge. Gradients on thousands of small rectangles
  // add texture the reader has to look past.
  roundRect(rect.x, rect.y, rect.w, rect.h, 0);
  ctx.fillStyle = hsl(base);
  ctx.fill();

  // With no gutter this edge is the whole grid, so it is a darker shade of the
  // block's own colour rather than a flat black wash: a fixed alpha that reads
  // correctly over a pale green leaf is invisible over a dark grey one, and the
  // map has both on screen at once.
  if (rect.w > 2 && rect.h > 2) {
    ctx.strokeStyle = hsl(base, isDark() ? -9 : -14);
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  state.cells.push({ index, kind, ...rect });
  if (kind === "child") {
    let i = index;
    let hops = 0;
    while (i >= 0 && hops < 128) {
      state.drawnUnder.set(i, (state.drawnUnder.get(i) || 0) + 1);
      if (i === 0) break;
      i = state.nodes[i].p;
      hops += 1;
    }
  }

  // Label only blocks big enough to read comfortably; a cramped label is noise.
  if (rect.w > 78 && rect.h > 22) {
    const light = base[2] > 55;
    ctx.save();
    roundRect(rect.x + 3, rect.y + 2, rect.w - 6, rect.h - 4, 0);
    ctx.clip();
    ctx.font = "11px -apple-system, system-ui, sans-serif";
    if (restCount > 0) {
      ctx.fillStyle = light ? "rgba(0,0,0,0.45)" : "rgba(255,255,255,0.5)";
      ctx.fillText(`${restCount} smaller`, rect.x + 6, rect.y + 15);
    } else {
      ctx.fillStyle = light ? "rgba(0,0,0,0.78)" : "rgba(255,255,255,0.93)";
      ctx.fillText(nameOf(index), rect.x + 6, rect.y + 15);
      if (rect.h > 38) {
        ctx.fillStyle = light ? "rgba(0,0,0,0.5)" : "rgba(255,255,255,0.6)";
        ctx.fillText(human(sizeOf(index)), rect.x + 6, rect.y + 29);
      }
    }
    ctx.restore();
  }
}

/** The selected node covering this cell, or null. Set lookup, not a linear scan. */
function selectedAncestor(index) {
  let i = index;
  let hops = 0;
  while (i >= 0 && hops < 128) {
    if (state.selected.has(i)) return i;
    if (i === 0) return null;
    i = state.nodes[i].p;
    hops += 1;
  }
  return null;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/**
 * Tint every selected cell, then outline each selected *folder* once around the
 * union of its cells. Outlining all 1,500 leaves individually reads as noise;
 * one crisp border per selection is what makes it obvious what is chosen.
 */
function drawSelection() {
  if (!state.selected.size) return;
  const accent = cssVar("--accent") || "#7db6f0";
  const bounds = new Map();

  ctx.save();
  ctx.fillStyle = "rgba(76, 155, 232, 0.36)";
  for (const cell of state.cells) {
    const owner = selectedAncestor(cell.index);
    if (owner === null) continue;
    roundRect(cell.x, cell.y, cell.w, cell.h, 0);
    ctx.fill();

    const b = bounds.get(owner) ?? { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity };
    b.x0 = Math.min(b.x0, cell.x);
    b.y0 = Math.min(b.y0, cell.y);
    b.x1 = Math.max(b.x1, cell.x + cell.w);
    b.y1 = Math.max(b.y1, cell.y + cell.h);
    bounds.set(owner, b);
  }

  ctx.strokeStyle = accent;
  ctx.lineWidth = 2;
  for (const b of bounds.values()) {
    roundRect(b.x0 - 1, b.y0 - 1, b.x1 - b.x0 + 2, b.y1 - b.y0 + 2, 0);
    ctx.stroke();
  }
  ctx.restore();
}

function drawHover() {
  if (state.hover < 0) return;
  const cell = state.cells.find((c) => c.index === state.hover);
  if (!cell) return;
  ctx.save();
  roundRect(cell.x, cell.y, cell.w, cell.h, 0);
  ctx.strokeStyle = isDark() ? "rgba(255,255,255,0.9)" : "rgba(0,0,0,0.75)";
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.restore();
}

function cellAt(x, y) {
  for (let i = state.cells.length - 1; i >= 0; i -= 1) {
    const c = state.cells[i];
    if (x >= c.x && x <= c.x + c.w && y >= c.y && y <= c.y + c.h) return c;
  }
  return null;
}

// ---------------------------------------------------------------------------
// panel
// ---------------------------------------------------------------------------

function renderChrome() {
  const crumbs = document.getElementById("crumbs");
  crumbs.innerHTML = "";
  ancestry(state.current).forEach((idx, i) => {
    if (i) {
      const sep = document.createElement("span");
      sep.className = "sep";
      sep.textContent = "›";
      crumbs.append(sep);
    }
    const btn = document.createElement("button");
    btn.textContent = idx === 0 ? state.rootPath.split("/").pop() || "/" : nameOf(idx);
    btn.onclick = () => {
      state.current = idx;
      render();
    };
    crumbs.append(btn);
  });
  document.getElementById("up").disabled = state.current === 0;
}

function renderFindings() {
  const groups = new Map();
  for (let i = 0; i < state.nodes.length; i += 1) {
    const node = state.nodes[i];
    if (!node.r) continue;
    if (!groups.has(node.r)) {
      groups.set(node.r, { id: node.r, tier: node.t, size: 0, nodes: [], regen: node.g });
    }
    const g = groups.get(node.r);
    g.size += node.s;
    g.nodes.push(i);
  }

  const order = { low: 0, medium: 1, high: 2 };
  const sorted = [...groups.values()].sort(
    (a, b) => order[a.tier] - order[b.tier] || b.size - a.size
  );

  const TIER_LABEL = {
    low: "Safe to delete",
    medium: "Reinstallable",
    high: "Review each",
  };

  const list = document.getElementById("findings");
  list.innerHTML = "";
  let lastTier = null;

  for (const g of sorted) {
    // One heading per tier, in words. Repeating a coloured dot on every row asks
    // the reader to decode the same thing over and over.
    if (g.tier !== lastTier) {
      lastTier = g.tier;
      const head = document.createElement("li");
      head.className = `tier-head ${g.tier}`;
      const sum = sorted
        .filter((x) => x.tier === g.tier)
        .reduce((s, x) => s + x.size, 0);
      head.innerHTML = `<span>${TIER_LABEL[g.tier]}</span><span class="sum">${human(sum)}</span>`;
      list.append(head);
    }

    const li = document.createElement("li");
    li.className = "rule";
    if (g.nodes.every((n) => state.selected.has(n))) li.classList.add("on");
    li.innerHTML = `
      <span class="size">${human(g.size)}</span>
      <span class="id">${g.id}</span>
      <span class="count">${g.nodes.length > 1 ? `×${g.nodes.length}` : ""}</span>
      <button class="reveal" title="Reveal in Finder" aria-label="Reveal ${g.id} in Finder">⤴</button>`;
    li.title = g.regen ? `restore: ${g.regen}` : "";
    // A group can stand for seventeen directories; the biggest one is the one
    // worth opening, and it is the one the size on this row is mostly made of.
    li.querySelector(".reveal").onclick = (e) => {
      e.stopPropagation();
      const biggest = g.nodes.reduce((a, b) => (sizeOf(b) > sizeOf(a) ? b : a));
      revealPath(pathOf(biggest));
    };
    li.onclick = () => {
      const allOn = g.nodes.every((n) => state.selected.has(n));
      for (const n of g.nodes) {
        if (allOn) state.selected.delete(n);
        else addSelection(n);
      }
      render();
    };
    list.append(li);
  }

  document.getElementById("reclaimable").textContent = human(
    sorted.reduce((s, g) => s + g.size, 0)
  );
}

function renderSelection() {
  const { bytes, unclassified, count } = selectionStats();
  document.getElementById("selected-count").textContent =
    count === 0 ? "Nothing selected" : `${count} selected`;
  document.getElementById("selected-size").textContent = human(bytes);
  document.getElementById("delete").disabled = count === 0;

  const warn = document.getElementById("unclassified-warning");
  if (unclassified > 0) {
    warn.hidden = false;
    warn.innerHTML =
      `<strong>${unclassified}</strong> of these are not matched by any rule. ` +
      `cachereaper cannot tell you how to get them back, and they may not be caches at all.`;
  } else {
    warn.hidden = true;
  }
}

function renderList() {
  const query = document.getElementById("finding-search").value;
  const tier = document.getElementById("tier-filter").value;
  const sort = document.getElementById("finding-sort").value;
  const filtered = filterSortFindings(state.findings, {
    query,
    tiers: tier === "all" ? ["low", "medium", "high"] : [tier],
    sort,
    direction: sort === "size" || sort === "age" ? "desc" : "asc",
  });
  const shown = visibleBatch(filtered, state.listPages);
  const body = document.querySelector("#finding-table tbody");
  body.innerHTML = "";
  for (const finding of shown) {
    const tr = document.createElement("tr");
    const checked = state.selected.has(finding.node_id);
    const referenceRoot = referenceRootFor(finding.path, appConfig?.reference_roots);
    tr.innerHTML = `<td><input type="checkbox" ${checked ? "checked" : ""} aria-label="Select ${finding.rule_id}"></td>
      <td class="mono">${human(finding.reclaimable_size)}</td><td>${finding.tier}</td>
      <td>${ageDays(finding.mtime).toFixed(0)}d</td><td>${finding.rule_id}</td>
      <td class="path"></td>`;
    tr.querySelector("td.path").textContent = finding.path;
    if (referenceRoot) {
      const input = tr.querySelector("input");
      input.disabled = true;
      input.title = `Protected by reference root ${referenceRoot}`;
    }
    const details = document.createElement("details");
    details.innerHTML = `<summary>Why matched / how to restore</summary><p></p>`;
    details.querySelector("p").textContent = `${finding.label}. ${finding.regen || "No regeneration guidance."}${finding.warning ? ` Warning: ${finding.warning}` : ""}`;
    tr.querySelector("td.path").append(details);
    tr.querySelector("input").onchange = () => {
      toggleSelection(finding.node_id);
      render();
    };
    body.append(tr);
  }
  const more = document.getElementById("load-more");
  more.hidden = shown.length >= filtered.length;
  document.getElementById("list-status").textContent = `${shown.length.toLocaleString()} of ${filtered.length.toLocaleString()} findings`;
}

function renderHealth() {
  if (!state.payload) return;
  const stats = state.payload.stats || {};
  const boundaries = [...(stats.unreadable_paths || []), ...(stats.excluded_paths || [])];
  const body = document.getElementById("health-body");
  body.innerHTML = `<dl>
    <dt>Reclaimable</dt><dd>${human(stats.reclaimable_bytes ?? stats.bytes ?? 0)}</dd>
    <dt>Allocated references</dt><dd>${human(stats.allocated_reference_bytes ?? 0)}</dd>
    <dt>Logical size</dt><dd>${human(stats.logical_bytes ?? 0)}</dd>
    <dt>Shared / snapshot</dt><dd>${human(stats.shared_or_snapshot_bytes ?? 0)}</dd>
    <dt>Volume capacity / free</dt><dd>${stats.volume_capacity == null ? "unavailable" : `${human(stats.volume_capacity)} / ${human(stats.volume_free)}`}</dd>
    <dt>Files / directories</dt><dd>${(stats.files || 0).toLocaleString()} / ${(stats.dirs || 0).toLocaleString()}</dd>
    <dt>User-excluded / unreadable</dt><dd>${stats.excluded || 0} / ${stats.unreadable || 0}</dd>
    <dt>Snapshot / live refresh</dt><dd>${state.payload.snapshot_saved ? "saved" : "not saved"} / ${state.payload.change_monitoring ? "watching" : "unavailable"}</dd>
    <dt>Duration</dt><dd>${((stats.elapsed_ms || 0) / 1000).toFixed(1)}s</dd></dl>`;
  const meta = document.createElement("p");
  meta.textContent = `Root: ${state.rootPath} · Platform: ${navigator.platform} · ${document.getElementById("app-version").textContent}`;
  body.append(meta);
  for (const warning of healthWarnings(stats)) {
    const p = document.createElement("p"); p.className = "health-warning"; p.textContent = warning; body.append(p);
  }
  if (boundaries.length) {
    const list = document.createElement("ul");
    for (const path of boundaries.slice(0, 20)) { const li = document.createElement("li"); li.textContent = path; list.append(li); }
    if (boundaries.length > 20) { const li = document.createElement("li"); li.textContent = `and ${boundaries.length - 20} more`; list.append(li); }
    body.append(list);
  }
}

function insightSection(title, subtitle = "") {
  const section = document.createElement("section");
  section.className = "insight-section";
  const header = document.createElement("header");
  const heading = document.createElement("h2");
  heading.textContent = title;
  header.append(heading);
  if (subtitle) {
    const copy = document.createElement("p");
    copy.textContent = subtitle;
    header.append(copy);
  }
  section.append(header);
  return section;
}

function signedHuman(value) {
  const number = Number(value || 0);
  return `${number > 0 ? "+" : number < 0 ? "−" : "±"}${human(Math.abs(number))}`;
}

function appendGrowthTable(section, label, changes) {
  if (!changes?.length) return;
  const heading = document.createElement("h3");
  heading.textContent = label;
  const table = document.createElement("table");
  table.className = "insight-table";
  table.innerHTML = "<thead><tr><th>Area</th><th class=\"number\">Allocated change</th><th class=\"number\">Files</th></tr></thead>";
  const body = document.createElement("tbody");
  for (const change of changes.slice(0, 12)) {
    const row = document.createElement("tr");
    row.innerHTML = '<td class="path"></td><td class="number"></td><td class="number"></td>';
    row.children[0].textContent = change.label;
    row.children[1].textContent = signedHuman(change.allocated_delta);
    row.children[2].textContent = Number(change.file_delta) > 0 ? `+${change.file_delta}` : String(change.file_delta);
    body.append(row);
  }
  table.append(body);
  section.append(heading, table);
}

function appendFileTable(section, files) {
  const table = document.createElement("table");
  table.className = "insight-table";
  table.innerHTML = "<thead><tr><th>File</th><th>Category</th><th class=\"number\">Allocated</th><th>Action</th></tr></thead>";
  const body = document.createElement("tbody");
  for (const file of visibleFileRows(files)) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    path.className = "path";
    path.textContent = file.path;
    const category = document.createElement("td");
    category.textContent = file.category;
    const size = document.createElement("td");
    size.className = "number";
    size.textContent = human(file.reclaimable_size);
    const action = document.createElement("td");
    const reveal = document.createElement("button");
    reveal.className = "ghost";
    reveal.textContent = "Reveal";
    reveal.onclick = () => revealPath(file.path);
    action.append(reveal);
    row.append(path, category, size, action);
    body.append(row);
  }
  table.append(body);
  section.append(table);
}

async function quarantineDuplicate(group, file, button) {
  const confirmed = window.confirm(
    `Move this duplicate into CacheReaper quarantine?\n\n${file.path}\n\n` +
      "Another fully verified copy must still exist. This is recoverable and does not free disk space yet."
  );
  if (!confirmed) return;
  button.disabled = true;
  button.textContent = "Verifying…";
  try {
    await call("quarantine_duplicate", {
      input: {
        scan_id: state.payload.scan_id,
        hash: group.hash,
        path: file.path,
      },
    });
    window.alert("The file was moved into quarantine. It can be restored from Quarantine history.");
    await runScan(state.rootPath);
  } catch (error) {
    window.alert(`Could not quarantine this file: ${error}`);
    button.disabled = false;
    button.textContent = "Quarantine…";
  }
}

async function trashDuplicate(group, file, button) {
  const confirmed = window.confirm(
    `Move this verified duplicate to the system Trash?\n\n${file.path}\n\n` +
      "CacheReaper will rehash this file and require another unchanged copy. If native Trash is unavailable, it will use recoverable Quarantine instead."
  );
  if (!confirmed) return;
  button.disabled = true;
  button.textContent = "Verifying…";
  try {
    const result = await call("trash_duplicate", {
      input: {
        scan_id: state.payload.scan_id,
        hash: group.hash,
        path: file.path,
      },
      fallbackToQuarantine: true,
    });
    window.alert(result.action === "quarantine"
      ? `Native Trash was unavailable, so the file was moved into CacheReaper Quarantine.\n\n${result.trash_error}`
      : "The file was moved to the system Trash and can be restored there.");
    await runScan(state.rootPath);
  } catch (error) {
    window.alert(`Could not move this file safely: ${error}`);
    button.disabled = false;
    button.textContent = "Trash…";
  }
}

function appendForecastSection(content, forecast) {
  if (!forecast) return;
  const confidence = Math.round(Number(forecast.confidence_millis || 0) / 10);
  const spanDays = Number(forecast.span_days_millis || 0) / 1000;
  const section = insightSection(
    "Storage forecast",
    `${Number(forecast.snapshot_count || 0)} local snapshots over ${spanDays.toFixed(1)} days · ${confidence}% confidence · estimate only`
  );
  const grid = document.createElement("div");
  grid.className = "insight-grid";
  const pressure = forecast.days_until_low_space == null
    ? "Not projected"
    : Number(forecast.days_until_low_space) < 1
      ? "Under 1 day"
      : `${Number(forecast.days_until_low_space).toLocaleString()} days`;
  for (const [value, label] of [
    [`${signedHuman(forecast.growth_bytes_per_day)}/day`, "median growth trend"],
    [pressure, "until 10% free space"],
    [String(forecast.anomalies?.length || 0), "new growth anomalies"],
  ]) {
    const metric = document.createElement("div");
    metric.className = "insight-metric";
    const strong = document.createElement("strong");
    strong.textContent = value;
    const span = document.createElement("span");
    span.textContent = label;
    metric.append(strong, span);
    grid.append(metric);
  }
  section.append(grid);
  if (forecast.anomalies?.length) {
    const table = document.createElement("table");
    table.className = "insight-table";
    table.innerHTML = "<thead><tr><th>Unexpected growth</th><th>Severity</th><th class=\"number\">Newest change</th><th class=\"number\">Prior median</th></tr></thead>";
    const body = document.createElement("tbody");
    for (const anomaly of forecast.anomalies) {
      const row = document.createElement("tr");
      row.innerHTML = '<td class="path"></td><td></td><td class="number"></td><td class="number"></td>';
      row.children[0].textContent = anomaly.label;
      row.children[1].textContent = anomaly.severity;
      row.children[2].textContent = signedHuman(anomaly.observed_delta_bytes);
      row.children[3].textContent = signedHuman(anomaly.baseline_delta_bytes);
      body.append(row);
    }
    table.append(body);
    section.append(table);
  }
  const note = document.createElement("p");
  note.className = "insight-note";
  note.textContent = forecast.explanation;
  section.append(note);
  content.append(section);
}

function appendProjectSection(content, projects) {
  if (!projects?.length) return;
  const section = insightSection(
    "Regenerable project storage",
    "Manifest and rule evidence only. Source code and repository metadata are never proposed for cleanup."
  );
  const table = document.createElement("table");
  table.className = "insight-table";
  table.innerHTML = "<thead><tr><th>Project</th><th>Evidence</th><th class=\"number\">Artifacts</th><th>Estimated recovery cost</th><th>Action</th></tr></thead>";
  const body = document.createElement("tbody");
  for (const project of projects) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    path.className = "path";
    path.textContent = project.root;
    const evidence = document.createElement("td");
    evidence.textContent = `${project.ecosystem} · ${project.manifest} · ${project.lockfile_present ? "lockfile" : "no lockfile observed"}`;
    const bytes = document.createElement("td");
    bytes.className = "number";
    bytes.textContent = human(project.artifact_bytes);
    const cost = document.createElement("td");
    cost.textContent = `${project.rebuild_cost} · ${formatDuration(project.estimated_regeneration_seconds)}${project.estimated_bandwidth_bytes == null ? "" : ` · up to ${human(project.estimated_bandwidth_bytes)} download`}`;
    const action = document.createElement("td");
    const reveal = document.createElement("button");
    reveal.className = "ghost";
    reveal.textContent = "Reveal";
    reveal.onclick = () => revealPath(project.root);
    action.append(reveal);
    row.append(path, evidence, bytes, cost, action);
    body.append(row);
  }
  table.append(body);
  section.append(table);
  content.append(section);
}

function appendOwnershipSection(content, ownership) {
  if (!ownership?.length) return;
  const section = insightSection(
    "Application ownership",
    "Names are compared with locally installed applications. A miss is a possible leftover, never proof of an uninstall."
  );
  const table = document.createElement("table");
  table.className = "insight-table";
  table.innerHTML = "<thead><tr><th>Application data</th><th>Status</th><th class=\"number\">Allocated</th><th>Action</th></tr></thead>";
  const body = document.createElement("tbody");
  for (const item of ownership) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    path.className = "path";
    path.textContent = item.path;
    const status = document.createElement("td");
    status.textContent = `${ownershipStateLabel(item.state)} · ${Math.round(Number(item.confidence_millis || 0) / 10)}%`;
    status.title = item.explanation;
    const bytes = document.createElement("td");
    bytes.className = "number";
    bytes.textContent = human(item.allocated_bytes);
    const action = document.createElement("td");
    const reveal = document.createElement("button");
    reveal.className = "ghost";
    reveal.textContent = "Reveal";
    reveal.onclick = () => revealPath(item.path);
    action.append(reveal);
    row.append(path, status, bytes, action);
    body.append(row);
  }
  table.append(body);
  section.append(table);
  content.append(section);
}

function appendSimilarMediaSection(content, media) {
  if (!media || (!media.complete && !(media.warnings || []).length)) return;
  const candidateCount = Number(media.image_candidates || 0) + Number(media.video_candidates || 0) + Number(media.audio_candidates || 0);
  const section = insightSection(
    "Similar media · review only",
    `${candidateCount.toLocaleString()} bounded candidates · ${Number(media.skipped || 0).toLocaleString()} unreadable/unsupported · perceptual images and sampled audio/video · similar never means duplicate`
  );
  if (!(media.groups || []).length) {
    const empty = document.createElement("p");
    empty.className = "insight-empty";
    empty.textContent = media.complete ? "No similar-media groups were found." : "Similar-media analysis did not complete.";
    section.append(empty);
  }
  for (const group of media.groups || []) {
    const details = document.createElement("details");
    details.className = "duplicate-group similar-group";
    const summary = document.createElement("summary");
    summary.textContent = `${group.files?.length || 0} similar ${group.kind} files`;
    const meta = document.createElement("span");
    meta.textContent = `${Math.round(Number(group.similarity_millis || 0) / 10)}% minimum match · ${group.algorithm}`;
    summary.append(meta);
    const list = document.createElement("ul");
    for (const file of group.files || []) {
      const item = document.createElement("li");
      const path = document.createElement("span");
      path.className = "path";
      path.textContent = file.path;
      const size = document.createElement("span");
      size.className = "mono";
      size.textContent = human(file.allocated_bytes);
      const reveal = document.createElement("button");
      reveal.className = "ghost";
      reveal.textContent = "Reveal";
      reveal.onclick = () => revealPath(file.path);
      item.append(path, size, reveal);
      list.append(item);
    }
    details.append(summary, list);
    section.append(details);
  }
  for (const warning of media.warnings || []) {
    const note = document.createElement("p");
    note.className = "insight-warning";
    note.textContent = warning;
    section.append(note);
  }
  content.append(section);
}

function appendOffloadSection(content, status) {
  if (!status) return;
  const section = insightSection("Offload connectors", offloadSummary(status));
  const note = document.createElement("p");
  note.className = "insight-note";
  note.textContent = `${status.per_request_consent_required ? "Per-request consent required" : "Consent policy unavailable"} · ${status.authority || "connector output has no cleanup authority"}`;
  section.append(note);
  content.append(section);
}

function appendAdvancedIntelligence(content, mode) {
  const intelligence = state.payload?.intelligence || {};
  appendForecastSection(content, intelligence.forecast);
  appendProjectSection(content, intelligence.projects);
  if (mode !== "cache") appendOwnershipSection(content, intelligence.ownership);
  if (mode === "all") appendSimilarMediaSection(content, state.payload?.media);
  appendOffloadSection(content, state.payload?.offload);
}

function renderInsights() {
  const mode = normalizeMode(state.scanMode);
  const details = MODE_DETAILS[mode];
  const analysis = state.payload?.analysis || {};
  const metrics = analysisMetrics(analysis);
  const advanced = advancedMetrics(state.payload);
  document.getElementById("insights-mode").textContent = details.label;
  document.getElementById("insights-summary").textContent = details.summary;
  const content = document.getElementById("insights-content");
  content.innerHTML = "";

  if (mode === "cache") {
    const section = insightSection("No personal-file inventory", "Cache Scan deliberately keeps the v1 privacy and memory profile.");
    const empty = document.createElement("p");
    empty.className = "insight-empty";
    empty.textContent = "Choose Whole Disk for metadata insights or All Files for locally proven exact duplicates.";
    section.append(empty);
    content.append(section);
    appendAdvancedIntelligence(content, mode);
    return;
  }

  const overview = insightSection("Overview", "Bounded, deterministic evidence from this scan snapshot.");
  const grid = document.createElement("div");
  grid.className = "insight-grid";
  const overviewItems = [
    [metrics.inventoryFiles.toLocaleString(), "inventoried files"],
    [metrics.categoryCount.toLocaleString(), "file categories"],
    [metrics.duplicateGroups.toLocaleString(), "exact duplicate groups"],
    [human(metrics.duplicateBytes), "potential duplicate savings"],
    [advanced.similarGroups.toLocaleString(), "similar-media groups"],
    [advanced.projects.toLocaleString(), "projects with artifacts"],
  ];
  for (const [value, label] of overviewItems) {
    const metric = document.createElement("div");
    metric.className = "insight-metric";
    const strong = document.createElement("strong");
    strong.textContent = value;
    const span = document.createElement("span");
    span.textContent = label;
    metric.append(strong, span);
    grid.append(metric);
  }
  overview.append(grid);
  content.append(overview);

  if (state.payload?.growth) {
    const growth = state.payload.growth;
    const elapsedDays = Number(growth.elapsed_ms || 0) / 86_400_000;
    const section = insightSection(
      "Since the previous snapshot",
      `${signedHuman(growth.allocated_delta)} allocated · ${Number(growth.file_delta) >= 0 ? "+" : ""}${growth.file_delta} files · ${elapsedDays < 1 ? "less than a day" : `${elapsedDays.toFixed(1)} days`}`
    );
    appendGrowthTable(section, "Category changes", growth.categories);
    appendGrowthTable(section, "Directory changes", growth.directories);
    content.append(section);
  }

  const categories = insightSection("Storage by category", "Allocated bytes; shared storage and sparse files may differ from logical size.");
  const categoryTable = document.createElement("table");
  categoryTable.className = "insight-table";
  categoryTable.innerHTML = "<thead><tr><th>Category</th><th class=\"number\">Files</th><th class=\"number\">Allocated</th><th class=\"number\">Logical</th></tr></thead>";
  const categoryBody = document.createElement("tbody");
  for (const category of analysis.categories || []) {
    const row = document.createElement("tr");
    row.innerHTML = `<td></td><td class="number"></td><td class="number"></td><td class="number"></td>`;
    row.children[0].textContent = category.category;
    row.children[1].textContent = category.files.toLocaleString();
    row.children[2].textContent = human(category.reclaimable_size);
    row.children[3].textContent = human(category.logical_size);
    categoryBody.append(row);
  }
  categoryTable.append(categoryBody);
  categories.append(categoryTable);
  content.append(categories);

  const largest = insightSection("Largest files", "Read-only results. Reveal a file to review it in the system file manager.");
  appendFileTable(largest, analysis.largest_files || []);
  content.append(largest);

  if ((analysis.old_large_files || []).length) {
    const old = insightSection("Old large files", "At least 10 MB and not modified for 90 days. Age alone never makes a file disposable.");
    appendFileTable(old, analysis.old_large_files);
    content.append(old);
  }

  if (mode === "all") {
    const duplicates = insightSection(
      "Exact duplicates",
      metrics.complete
        ? `Every member has a complete SHA-256. This scan reused ${Number(analysis.hash_cache_hits || 0).toLocaleString()} cached hashes and computed ${Number(analysis.hash_cache_misses || 0).toLocaleString()}.`
        : "Content analysis did not complete; no duplicate action is available."
    );
    if (!(analysis.duplicate_groups || []).length) {
      const empty = document.createElement("p");
      empty.className = "insight-empty";
      empty.textContent = metrics.complete
        ? "No exact duplicates at least 1 MB were found."
        : "Duplicate analysis was cancelled or unavailable.";
      duplicates.append(empty);
    }
    for (const group of analysis.duplicate_groups || []) {
      const detailsEl = document.createElement("details");
      detailsEl.className = "duplicate-group";
      const summary = document.createElement("summary");
      summary.textContent = `${group.files.length} identical files`;
      const meta = document.createElement("span");
      meta.textContent = `${human(group.reclaimable_size)} potential savings`;
      summary.append(meta);
      const list = document.createElement("ul");
      for (const file of group.files) {
        const item = document.createElement("li");
        const path = document.createElement("span");
        path.className = "path";
        path.textContent = file.path;
        const reveal = document.createElement("button");
        reveal.className = "ghost";
        reveal.textContent = "Reveal";
        reveal.onclick = () => revealPath(file.path);
        const quarantine = document.createElement("button");
        quarantine.className = "ghost quarantine";
        const referenceRoot = referenceRootFor(file.path, appConfig?.reference_roots);
        quarantine.textContent = referenceRoot ? "Reference copy" : "Quarantine…";
        quarantine.disabled = Boolean(referenceRoot);
        quarantine.title = referenceRoot
          ? `Protected by reference root ${referenceRoot}`
          : "Move this verified duplicate into recoverable quarantine";
        quarantine.onclick = referenceRoot ? null : () => quarantineDuplicate(group, file, quarantine);
        const trash = document.createElement("button");
        trash.className = "ghost trash";
        trash.textContent = referenceRoot ? "Protected" : "Trash…";
        trash.disabled = Boolean(referenceRoot);
        trash.title = referenceRoot
          ? `Protected by reference root ${referenceRoot}`
          : "Move this verified duplicate to the system Trash";
        trash.onclick = referenceRoot ? null : () => trashDuplicate(group, file, trash);
        item.append(path, reveal, trash, quarantine);
        list.append(item);
      }
      detailsEl.append(summary, list);
      duplicates.append(detailsEl);
    }
    for (const warning of analysis.warnings || []) {
      const p = document.createElement("p");
      p.className = "insight-warning";
      p.textContent = warning;
      duplicates.append(p);
    }
    content.append(duplicates);
  }
  appendAdvancedIntelligence(content, mode);
}

function renderEvidenceResults(insights, container) {
  container.innerHTML = "";
  const rows = sortedInsights(insights);
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "insight-empty";
    empty.textContent = "No current insight matches this filter.";
    container.append(empty);
    return;
  }
  for (const insight of rows) {
    const article = document.createElement("article");
    article.className = "evidence-card";
    const heading = document.createElement("div");
    heading.className = "evidence-heading";
    const title = document.createElement("strong");
    title.textContent = insight.title;
    const size = document.createElement("span");
    size.className = "mono";
    size.textContent = human(insight.estimated_reclaimable_bytes || 0);
    heading.append(title, size);
    const explanation = document.createElement("p");
    explanation.textContent = insight.explanation;
    const meta = document.createElement("p");
    meta.className = "evidence-meta";
    meta.textContent = `${String(insight.kind || "insight").replaceAll("-", " ")} · ${insight.risk} risk · ${insight.provenance} evidence · ${Math.round((insight.confidence_millis || 0) / 10)}% confidence`;
    const path = document.createElement("code");
    path.textContent = insight.paths?.[0] || "No path supplied";
    article.append(heading, explanation, meta, path);
    if ((insight.paths?.length || 0) > 1) {
      const more = document.createElement("small");
      more.textContent = ` +${insight.paths.length - 1} verified path${insight.paths.length === 2 ? "" : "s"}`;
      article.append(more);
    }
    container.append(article);
  }
}

function renderPlan(plan) {
  const container = document.getElementById("plan-results");
  container.innerHTML = "";
  const summary = document.createElement("section");
  summary.className = `plan-summary ${plan.target_met ? "met" : "short"}`;
  const heading = document.createElement("strong");
  heading.textContent = planSummary(plan, human);
  const detail = document.createElement("p");
  detail.textContent = `Policy: ${String(plan.policy).replaceAll("-", " ")} · about ${Number(plan.estimated_time_seconds || 0).toLocaleString()}s · rebuild ${String(plan.estimated_rebuild_cost || "none").replaceAll("-", " ")} · bandwidth ${plan.estimated_bandwidth_bytes == null ? "unknown" : human(plan.estimated_bandwidth_bytes)} · snapshot ${plan.snapshot_id}`;
  summary.append(heading, detail);
  container.append(summary);

  for (const action of plan.actions || []) {
    const article = document.createElement("article");
    article.className = "plan-action";
    const head = document.createElement("div");
    head.className = "evidence-heading";
    const title = document.createElement("strong");
    title.textContent = String(action.kind).replaceAll("-", " ");
    const bytes = document.createElement("span");
    bytes.className = "mono";
    bytes.textContent = human(action.estimated_reclaimable_bytes || 0);
    head.append(title, bytes);
    const explanation = document.createElement("p");
    explanation.textContent = action.explanation;
    const meta = document.createElement("p");
    meta.className = "evidence-meta";
    meta.textContent = `${action.risk} risk · ${String(action.recoverability).replaceAll("-", " ")} · ${String(action.reclaim_timing).replaceAll("-", " ")}`;
    const path = document.createElement("code");
    path.textContent = action.paths?.join(" · ") || "";
    article.append(head, explanation, meta, path);
    container.append(article);
  }

  if ((plan.risks || []).length) {
    const risks = document.createElement("ul");
    risks.className = "plan-risks";
    for (const risk of plan.risks) { const item = document.createElement("li"); item.textContent = risk; risks.append(item); }
    container.append(risks);
  }

  const selectable = (plan.actions || []).flatMap((action) => action.kind === "purge-cache" ? (action.node_ids || []) : []);
  if (selectable.length) {
    const select = document.createElement("button");
    select.className = "ghost plan-select";
    select.textContent = `Review ${selectable.length} cache action${selectable.length === 1 ? "" : "s"} on map`;
    select.onclick = () => {
      state.selected = new Set(selectable.filter((node) => state.nodes[node]));
      state.mode = "select";
      selectView("map");
    };
    container.append(select);
  }
}

function render() {
  renderChrome();
  renderFindings();
  renderSelection();
  renderList();
  renderInsights();
  renderHealth();
  if (state.view === "map") draw();
}

function selectView(view, shouldRender = true) {
  state.view = view;
  document.getElementById("map-wrap").hidden = view !== "map";
  document.getElementById("list-wrap").hidden = view !== "list";
  document.getElementById("insights-wrap").hidden = view !== "insights";
  document.getElementById("ask-wrap").hidden = view !== "ask";
  document.getElementById("plan-wrap").hidden = view !== "plan";
  for (const peer of document.querySelectorAll("#view-mode button")) {
    const on = peer.dataset.view === view;
    peer.classList.toggle("on", on);
    peer.setAttribute("aria-selected", String(on));
  }
  if (view === "map") resize();
  if (shouldRender) render();
}

for (const button of document.querySelectorAll("#view-mode button")) {
  button.onclick = () => selectView(button.dataset.view);
}
for (const id of ["finding-search", "tier-filter", "finding-sort"]) {
  document.getElementById(id).addEventListener(id === "finding-search" ? "input" : "change", () => {
    state.listPages = 1; renderList();
  });
}
document.getElementById("load-more").onclick = () => { state.listPages += 1; renderList(); };

document.getElementById("ask-form").onsubmit = async (event) => {
  event.preventDefault();
  const error = document.getElementById("ask-error");
  error.hidden = true;
  try {
    if (!state.payload?.scan_id) throw new Error("Run a scan first");
    const result = await call("insight_query", { input: { scan_id: state.payload.scan_id, query: document.getElementById("ask-query").value } });
    const chips = document.getElementById("ask-ast");
    chips.innerHTML = "";
    for (const clause of result.ast.clauses || []) {
      const chip = document.createElement("span");
      chip.textContent = clauseLabel(clause);
      chips.append(chip);
    }
    renderEvidenceResults(result.matches, document.getElementById("ask-results"));
  } catch (reason) {
    error.textContent = String(reason);
    error.hidden = false;
    document.getElementById("ask-results").innerHTML = "";
  }
};

document.getElementById("plan-form").onsubmit = async (event) => {
  event.preventDefault();
  const error = document.getElementById("plan-error");
  error.hidden = true;
  try {
    if (!state.payload?.scan_id) throw new Error("Run a scan first");
    const target = targetBytes(document.getElementById("plan-target").value, document.getElementById("plan-unit").value);
    if (!target) throw new Error("Enter a positive storage target");
    const query = document.getElementById("plan-query").value.trim();
    const plan = await call("cleanup_plan", { input: { scan_id: state.payload.scan_id, target_bytes: target, policy: document.getElementById("plan-policy").value, query: query || null } });
    renderPlan(plan);
  } catch (reason) {
    error.textContent = String(reason);
    error.hidden = false;
    document.getElementById("plan-results").innerHTML = "";
  }
};

call("local_ai_status").then((status) => {
  const badge = document.getElementById("local-ai-badge");
  badge.textContent = status.enabled ? "Local AI enabled · presentation only" : "Deterministic · model optional";
  badge.title = `${status.privacy}; ${status.authority}`;
}).catch(() => {});

document.getElementById("copy-diagnostics").onclick = async () => {
  const report = diagnostics(state.payload || {}, {
    home: state.payload?.home_path || "",
    platform: navigator.platform,
    version: document.getElementById("app-version").textContent.replace("cachereaper ", ""),
  });
  try {
    await navigator.clipboard.writeText(report);
    setStatus("Diagnostics copied — nothing was sent");
  } catch (_) {
    const fallback = document.getElementById("diagnostics-fallback");
    fallback.hidden = false; fallback.value = report; fallback.select();
    setStatus("Select and copy the diagnostics below");
  }
};

// ---------------------------------------------------------------------------
// interaction
// ---------------------------------------------------------------------------

function localPoint(e) {
  const rect = box();
  return { x: e.clientX - rect.left, y: e.clientY - rect.top };
}

canvas.addEventListener("mousedown", (e) => {
  if (state.mode !== "select" || e.altKey) return;
  const p = localPoint(e);
  state.drag = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, moved: false };
});

window.addEventListener("mousemove", (e) => {
  if (!state.drag) return;
  const p = localPoint(e);
  state.drag.x1 = p.x;
  state.drag.y1 = p.y;
  if (Math.abs(p.x - state.drag.x0) > 3 || Math.abs(p.y - state.drag.y0) > 3) {
    state.drag.moved = true;
  }
  if (state.drag.moved) {
    const r = dragRect();
    marqueeEl.hidden = false;
    marqueeEl.style.left = `${r.x}px`;
    marqueeEl.style.top = `${r.y}px`;
    marqueeEl.style.width = `${r.w}px`;
    marqueeEl.style.height = `${r.h}px`;
  }
});

function dragRect() {
  const d = state.drag;
  return {
    x: Math.min(d.x0, d.x1),
    y: Math.min(d.y0, d.y1),
    w: Math.abs(d.x1 - d.x0),
    h: Math.abs(d.y1 - d.y0),
  };
}

window.addEventListener("mouseup", () => {
  if (!state.drag) return;
  const { moved } = state.drag;
  const r = dragRect();
  state.drag = null;
  marqueeEl.hidden = true;
  if (!moved) return;
  // the click event that follows a drag must not also toggle a block
  lastDragEnd = performance.now();

  const hits = state.cells
    .filter((c) => c.kind === "child")
    .filter((c) => c.x < r.x + r.w && c.x + c.w > r.x && c.y < r.y + r.h && c.y + c.h > r.y)
    .map((c) => c.index);
  if (!hits.length) return;

  for (const node of collapseToFolders(new Set(hits))) addSelection(node);
  render();
});

canvas.addEventListener("mousemove", (e) => {
  const p = localPoint(e);
  const cell = cellAt(p.x, p.y);
  const index = cell ? cell.index : -1;
  if (index !== state.hover) {
    state.hover = index;
    draw();
  }
  if (index < 0 || state.drag) {
    tooltip.hidden = true;
    return;
  }
  const node = state.nodes[index];
  const age = node.m ? Math.round((Date.now() / 1000 - node.m) / 86400) : null;
  tooltip.hidden = false;
  const path = document.createElement("div");
  path.className = "path";
  path.textContent = pathOf(index);

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.append(`${human(node.s)} · ${node.f.toLocaleString()} files`);
  if (age !== null) meta.append(` · ${age}d old`);
  if (node.r) {
    meta.append(" · ");
    const rule = document.createElement("strong");
    rule.textContent = node.r;
    meta.append(rule, ` (${node.t})`);
  } else {
    meta.append(" · unclassified");
  }

  const parts = [path, meta];
  if (node.g) {
    const regen = document.createElement("div");
    regen.className = "regen";
    regen.textContent = `restore: ${node.g}`;
    parts.push(regen);
  }
  tooltip.replaceChildren(...parts);
  const pad = 16;
  tooltip.style.left = `${Math.min(e.clientX + pad, window.innerWidth - tooltip.offsetWidth - 8)}px`;
  tooltip.style.top = `${Math.min(e.clientY + pad, window.innerHeight - tooltip.offsetHeight - 8)}px`;
});

canvas.addEventListener("mouseleave", () => {
  tooltip.hidden = true;
  state.hover = -1;
  draw();
});

canvas.addEventListener("click", (e) => {
  if (performance.now() - lastDragEnd < 200) return;
  const p = localPoint(e);
  const cell = cellAt(p.x, p.y);
  if (!cell) return;

  const wantsSelect = state.mode === "select" ? !e.altKey : e.metaKey || e.ctrlKey;

  if (wantsSelect) {
    if (cell.kind === "rest") return; // stands for many siblings, not one thing
    // In explore mode a modifier-click snaps to the nearest claimed folder,
    // which is almost always what is meant. In select mode the block you
    // clicked is what you get.
    let target = cell.index;
    if (state.mode !== "select") {
      let hops = 0;
      while (target > 0 && !ruleOf(target) && hops < 64) {
        target = state.nodes[target].p;
        hops += 1;
      }
      if (!ruleOf(target)) return;
    }
    toggleSelection(target);
    render();
    return;
  }

  const chain = ancestry(cell.index);
  const next = chain[ancestry(state.current).length] ?? cell.index;
  if (next !== state.current && (state.nodes[next].c || []).length) {
    state.current = next;
    render();
  }
});

// ---------------------------------------------------------------------------
// reveal
// ---------------------------------------------------------------------------

const menuEl = document.getElementById("context-menu");

/**
 * Hand a path to Finder.
 *
 * The Rust side confines this to the same roots deletion is confined to, so a
 * refusal here means the tree and the session disagree about what was scanned —
 * worth showing rather than swallowing.
 */
async function revealPath(path) {
  if (!inTauri) {
    setStatus("Reveal in Finder needs the desktop app");
    return;
  }
  try {
    await call("reveal", { path });
  } catch (err) {
    setStatus(`could not reveal: ${err}`);
  }
}

function closeMenu() {
  menuEl.hidden = true;
  menuEl.dataset.path = "";
}

function openMenu(x, y, path, index) {
  menuEl.dataset.path = path;
  menuEl.dataset.node = String(index);
  menuEl.querySelector(".path").textContent = path;
  menuEl.hidden = false;
  for (const action of ["exclude-profile", "exclude-rule-profile"]) {
    menuEl.querySelector(`[data-action="${action}"]`).hidden = !state.activeProfileId;
  }
  const hasRule = !!ruleOf(index);
  menuEl.querySelector('[data-action="exclude-rule-global"]').hidden = !hasRule;
  menuEl.querySelector('[data-action="exclude-rule-profile"]').hidden = !hasRule || !state.activeProfileId;
  // Measure after unhiding, then keep it inside the window: a right-click near
  // the bottom edge is exactly where a menu wants to hang off the screen.
  const pad = 8;
  menuEl.style.left = `${Math.min(x, window.innerWidth - menuEl.offsetWidth - pad)}px`;
  menuEl.style.top = `${Math.min(y, window.innerHeight - menuEl.offsetHeight - pad)}px`;
}

canvas.addEventListener("contextmenu", (e) => {
  e.preventDefault();
  const p = localPoint(e);
  const cell = cellAt(p.x, p.y);
  // "rest" stands for a run of siblings too small to draw, so there is no one
  // path behind it to open.
  if (!cell || cell.kind === "rest") {
    closeMenu();
    return;
  }
  tooltip.hidden = true;
  openMenu(e.clientX, e.clientY, pathOf(cell.index), cell.index);
});

menuEl.querySelector('[data-action="reveal"]').onclick = () => {
  const path = menuEl.dataset.path;
  closeMenu();
  if (path) revealPath(path);
};

async function applyContextExclusion(action) {
  const path = menuEl.dataset.path;
  const node = Number(menuEl.dataset.node);
  const profile = action.endsWith("profile") ? state.activeProfileId : null;
  const ruleAction = action.includes("rule");
  const subject = ruleAction ? ruleOf(node) : path;
  if (!subject || !window.confirm(`Exclude ${subject}${profile ? " from this profile" : " globally"} and rescan?`)) return;
  closeMenu();
  try {
    if (ruleAction) await call("exclusion_add_rule", { ruleId: subject, profileId: profile });
    else await call("exclusion_add_path", { path: subject, profileId: profile });
    await refreshProfiles();
    runScan(state.rootPath);
  } catch (error) { window.alert(`Could not save exclusion: ${error}`); }
}
for (const action of ["exclude-global", "exclude-profile", "exclude-rule-global", "exclude-rule-profile"]) {
  menuEl.querySelector(`[data-action="${action}"]`).onclick = () => applyContextExclusion(action);
}

window.addEventListener("mousedown", (e) => {
  if (!menuEl.hidden && !menuEl.contains(e.target)) closeMenu();
});
window.addEventListener("blur", closeMenu);

function setMode(mode) {
  state.mode = mode;
  document.body.classList.toggle("mode-select", mode === "select");
  for (const btn of document.querySelectorAll("#mode button")) {
    const on = btn.dataset.mode === mode;
    btn.classList.toggle("on", on);
    btn.setAttribute("aria-selected", String(on));
  }
}

for (const btn of document.querySelectorAll("#mode button")) {
  btn.onclick = () => setMode(btn.dataset.mode);
}

document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
  // While a sheet is up there is no map to drive, and `s` would silently flip a
  // mode the user cannot see.
  if (!onboarding.hidden) {
    if (e.key === "Escape" && reviewing) closeAccess();
    return;
  }

  if ((e.metaKey || e.ctrlKey) && (e.key === "r" || e.key === "R")) {
    // Whatever the pointer is over, else a selection of exactly one — `open -R`
    // reveals a single path, and picking one out of many would be a guess.
    const only = state.selected.size === 1 ? [...state.selected][0] : -1;
    const target = state.hover >= 0 ? state.hover : only;
    if (target >= 0) {
      e.preventDefault();
      revealPath(pathOf(target));
    }
    return;
  }

  if (e.key === "Backspace" || e.key === "ArrowUp") {
    if (state.current !== 0) {
      state.current = state.nodes[state.current].p;
      render();
      e.preventDefault();
    }
  } else if (e.key === "Escape") {
    if (!menuEl.hidden) {
      closeMenu();
      return;
    }
    state.selected.clear();
    render();
  } else if (e.key === "s" || e.key === "S") {
    setMode(state.mode === "select" ? "explore" : "select");
  }
});

document.getElementById("up").onclick = () => {
  if (state.current !== 0) {
    state.current = state.nodes[state.current].p;
    render();
  }
};

document.getElementById("colour-mode").onchange = (e) => {
  state.colourMode = e.target.value;
  draw();
};

document.getElementById("select-low").onclick = () => {
  for (let i = 0; i < state.nodes.length; i += 1) {
    if (state.nodes[i].t === "low") addSelection(i);
  }
  render();
};

document.getElementById("clear").onclick = () => {
  state.selected.clear();
  render();
};

document.getElementById("delete").onclick = async () => {
  const { high, unclassified, count, bytes } = selectionStats();
  const targets = [...state.selected].map((i) => ({
    path: pathOf(i),
    rule_id: ruleOf(i),
    tier: state.nodes[i].t || null,
    expect_name: nameOf(i),
    size: sizeOf(i),
    label: state.findings.find((finding) => finding.node_id === i)?.label || "",
    regen: state.findings.find((finding) => finding.node_id === i)?.regen || state.nodes[i].g || "",
  }));

  // Anything the rules did not claim is treated as seriously as a high-risk
  // finding: there is no regen note for it and no evidence it is a cache.
  if (high > 0 || unclassified > 0) {
    const phrase = high > 0 ? "delete high risk" : "delete unclassified";
    const typed = window.prompt(
      `${count} item(s), ${human(bytes)}.\n` +
        (high ? `${high} high risk. ` : "") +
        (unclassified ? `${unclassified} not matched by any rule. ` : "") +
        `\n\nType "${phrase}" to confirm.`
    );
    if (typed !== phrase) return;
  } else if (!window.confirm(`Delete ${count} item(s), ${human(bytes)}?`)) {
    return;
  }

  if (!inTauri) {
    window.alert("Deletion is only available inside the desktop app.");
    return;
  }
  try {
    const result = await call("delete_targets", { targets });
    const skipped = result.skipped?.length
      ? `\n\n${result.skipped.length} skipped:\n${result.skipped.join("\n")}`
      : "";
    window.alert(`Freed ${human(result.freed)} across ${result.removed} paths.${skipped}`);
    // Rescan the same root rather than reloading the page: a reload would drop
    // back to $HOME and throw away whichever folder the user chose.
    await runScan(state.rootPath);
  } catch (err) {
    console.error(err);
    window.alert(`Could not delete the selection: ${String(err)}`);
  }
};

window.addEventListener("resize", resize);
document.getElementById("refresh-snapshot").onclick = () => runScan(state.rootPath);

// Debug/test hook: lets browser-driven UI checks assert on internal state and
// exercise selection through the real code path rather than poking the Set.
window.__cachereaper = state;
window.__cachereaper.api = { addSelection, toggleSelection, collapseToFolders, covers, render };

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

function applyPayload(data) {
  // A scan of a different root invalidates every index we were holding, so the
  // view is reset wholesale rather than patched.
  state.nodes = data.nodes;
  state.rootPath = data.root_path;
  state.stats = data.stats;
  state.payload = data;
  document.getElementById("change-notice").hidden = true;
  setScanMode(data.mode || state.scanMode);
  state.findings = Array.isArray(data.findings)
    ? data.findings.map((finding) => ({ ...finding, mtime: data.nodes[finding.node_id]?.m || 0 }))
    : data.nodes.flatMap((node, node_id) => node.r ? [{
        node_id, rule_id: node.r, tier: node.t, label: node.r, regen: node.g || "",
        warning: "", source: "snapshot", reclaimable_size: node.s,
        path: "", mtime: node.m,
      }] : []);
  for (const finding of state.findings) {
    if (!finding.path) finding.path = pathOf(finding.node_id);
  }
  state.current = 0;
  state.selected.clear();
  state.hover = -1;
  state.drag = null;
  selectView(state.scanMode === "cache" ? "map" : "insights", false);

  document.getElementById("total").textContent = human(data.stats.reclaimable_bytes ?? data.stats.bytes);

  // Two unrelated denials produce this number — a folder the user refused, and
  // the ~/Library directories that have no dialog at all — and the difference
  // decides what to do about it. Rather than guess which is which from a count,
  // this states the fact and hands over to the sheet that knows both.
  const warn = document.getElementById("warning");
  if (data.stats.unreadable > 0) {
    warn.hidden = false;
    document.getElementById("warning-text").textContent =
      `${data.stats.unreadable} directories could not be read, so their contents are ` +
      `not counted.`;
  } else {
    warn.hidden = true;
  }

  setStatus(
    `${data.stats.files.toLocaleString()} files · ${data.stats.dirs.toLocaleString()} dirs · ` +
      `${(data.stats.elapsed_ms / 1000).toFixed(1)}s`
  );
  resize();
  render();
}

/**
 * Scan `path` (or $HOME) and swap the map over to it.
 *
 * Guarded by `scanning` because a second walk kicked off while the first is
 * still running would race to call applyPayload, and the loser would leave the
 * crumbs pointing at one root and the nodes at another.
 */
let scanning = false;

const onboarding = document.getElementById("onboarding");
const onboardError = document.getElementById("onboard-error");

const scanningEl = document.getElementById("scanning");

async function runScan(path) {
  if (scanning) return;
  const hadTree = state.nodes.length > 0;
  hideHome();
  scanning = true;
  activeScanId = typeof crypto?.randomUUID === "function"
    ? crypto.randomUUID() : `scan-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  document.body.classList.add("busy");
  onboardError.hidden = true;

  document.getElementById("scan-path").textContent = path || "your home folder";
  document.getElementById("scan-counts").textContent = "counting…";
  scanningEl.querySelector("h2").textContent =
    state.scanMode === "all" ? "Reading and hashing candidates" : "Reading the tree";
  scanningEl.hidden = false;
  const cancel = document.getElementById("cancel-scan");
  Object.assign(cancel, { disabled: cancelViewState(false).disabled, textContent: cancelViewState(false).label });

  setStatus("scanning…");
  try {
    const request = {
      schema: 2,
      scan_id: activeScanId,
      mode: state.scanMode,
      root: state.activeProfileId ? null : (path || state.rootPath || null),
      profile_id: state.activeProfileId,
      excluded_paths: [],
      excluded_rules: [],
    };
    applyPayload(await load(request));
    onboarding.hidden = true;
  } catch (err) {
    const cancelled = String(err).toLocaleLowerCase().includes("cancelled");
    if (cancelled && hadTree) {
      setStatus("Scan cancelled — previous results kept");
      return;
    }
    // Come back to the journey if we never got a tree: an empty map with the
    // sheet gone is a dead end.
    setStatus(null);
    showHome(cancelled ? "Scan cancelled" : `Could not scan this folder: ${String(err)}`);
    console.error(err);
  } finally {
    scanning = false;
    activeScanId = null;
    scanningEl.hidden = true;
    document.body.classList.remove("busy");
  }
}

document.getElementById("cancel-scan").onclick = async () => {
  if (!activeScanId) return;
  const button = document.getElementById("cancel-scan");
  const view = cancelViewState(true);
  button.textContent = view.label;
  button.disabled = view.disabled;
  try { await call("cancel_scan", { scanId: activeScanId }); } catch (error) { console.error(error); }
};

/** Native folder chooser. Resolves to null when the user cancels. */
async function chooseFolder() {
  if (scanning || !inTauri) return null;
  const { invoke } = window.__TAURI__.core;
  return invoke("pick_folder");
}

// ---------------------------------------------------------------------------
// updates
// ---------------------------------------------------------------------------
//
// The app checks on launch and then says nothing unless there is something to
// say. It never installs on its own: this tool deletes files, and swapping the
// binary that does that without being asked is not a thing to do quietly. So the
// automatic half is the *looking*, and the deciding stays with the user.

const updateCard = document.getElementById("update-card");
const homeUpdate = document.getElementById("home-update");
const updateStatusEl = document.getElementById("update-status");
const updateLook = document.getElementById("update-look");
const updateAuto = document.getElementById("update-auto");
const updateInstall = document.getElementById("update-install");
const homeUpdateInstall = document.getElementById("home-update-install");

const updateInstallButtons = [updateInstall, homeUpdateInstall];

// Guards the one action that must not be started twice. The Rust side keeps the
// pending update available after a failed download so this button can retry.
let installing = false;
let updateProgressBound = false;

function updateSays(text) {
  updateStatusEl.hidden = text === null;
  if (text !== null) updateStatusEl.textContent = text;
}

function showUpdate(info) {
  document.getElementById("update-headline").textContent = `Version ${info.version} is out`;
  document.getElementById("update-version").textContent = `you have ${info.current}`;
  const notes = document.getElementById("update-notes");
  const body = (info.notes ?? "").trim();
  notes.hidden = !body;
  notes.textContent = body;
  updateCard.hidden = false;
  document.getElementById("home-update-headline").textContent = `Version ${info.version} is ready`;
  document.getElementById("home-update-copy").textContent =
    `You have ${info.current}. Downloaded updates are verified before installation.`;
  homeUpdate.hidden = false;
  updateSays(null);
}

/**
 * @param manual true when the user pressed the button, which is the only case
 *   that reports "you are up to date" or an error. A launch check that finds
 *   nothing, or that cannot reach the network, says nothing at all — being
 *   offline is not news, and neither is already being current.
 */
async function lookForUpdate(manual) {
  if (manual) {
    updateLook.disabled = true;
    updateSays("checking…");
  }
  try {
    const info = await call("update_check");
    if (info) showUpdate(info);
    else {
      updateCard.hidden = true;
      homeUpdate.hidden = true;
      if (manual) updateSays("You have the newest version.");
    }
  } catch (err) {
    console.error(err);
    if (manual) updateSays(`Could not check: ${err}`);
  } finally {
    updateLook.disabled = false;
  }
}

updateLook.onclick = () => lookForUpdate(true);

function dismissUpdate() {
  // For this session only. A build worth telling you about once is worth
  // telling you about again next launch, and a setting to silence one specific
  // version is a setting that has to be got right forever.
  updateCard.hidden = true;
  homeUpdate.hidden = true;
}

document.getElementById("update-later").onclick = dismissUpdate;
document.getElementById("home-update-later").onclick = dismissUpdate;

updateAuto.onchange = async () => {
  try {
    await call("set_auto_update", { on: updateAuto.checked });
  } catch (err) {
    console.error(err);
    updateAuto.checked = !updateAuto.checked;
    updateSays("Could not save that setting.");
  }
};

async function installUpdate() {
  if (installing) return;
  installing = true;
  for (const button of updateInstallButtons) {
    button.disabled = true;
    button.textContent = "Downloading…";
  }

  try {
    if (inTauri && !updateProgressBound) {
      const { listen } = window.__TAURI__.event;
      await listen("update-progress", ({ payload }) => {
        // The manifest carries a length for both platforms, but a proxy that
        // strips it would otherwise leave the button reading "NaN%".
        const label = payload.total
          ? `Downloading ${Math.round((payload.downloaded / payload.total) * 100)}%`
          : `Downloading ${human(payload.downloaded)}`;
        for (const button of updateInstallButtons) button.textContent = label;
      });
      updateProgressBound = true;
    }
    // On success this never returns: the app is replaced and restarted.
    await call("update_install");
  } catch (err) {
    console.error(err);
    installing = false;
    for (const button of updateInstallButtons) {
      button.disabled = false;
      button.textContent = "Install and restart";
    }
    updateSays(`Update failed: ${err}`);
  }
}

updateInstall.onclick = installUpdate;
homeUpdateInstall.onclick = installUpdate;

/** Version line, the switch, and a launch check started as soon as config arrives. */
async function initUpdates(config) {
  updateAuto.checked = config.auto_update !== false;
  // Start this before any scope/profile work. The card is rendered on the home
  // screen, so an available update is actionable as soon as the app opens — it
  // is not held behind a completed scan.
  if (updateAuto.checked) void lookForUpdate(false);
  try {
    document.getElementById("app-version").textContent = `cachereaper ${await call("app_version")}`;
    renderHealth();
  } catch (err) {
    console.error(err);
  }
}

// ---------------------------------------------------------------------------
// support
// ---------------------------------------------------------------------------

const supportCard = document.getElementById("support-card");
let supportTimer = null;

function queueSupportCheck(nextAt) {
  if (supportTimer !== null) clearTimeout(supportTimer);
  supportTimer = null;
  if (nextAt === null || nextAt === undefined) return;
  const delay = Math.max(0, nextAt * 1000 - Date.now());
  supportTimer = window.setTimeout(initSupport, Math.min(delay, 2_147_000_000));
}

async function initSupport() {
  try {
    const prompt = await call("support_prompt_status");
    supportCard.hidden = !prompt.show;
    queueSupportCheck(prompt.show ? null : prompt.next_at);
  } catch (err) {
    // A support prompt must never interfere with the disk tool itself.
    console.error(err);
    supportCard.hidden = true;
  }
}

async function openSupport(destination) {
  await call("open_support_page", { destination });
}

document.getElementById("support-open").onclick = () => {
  openSupport("coffee").catch((err) => {
    console.error(err);
    setStatus(`could not open the support page: ${String(err)}`);
  });
};

async function followSupportLink(destination) {
  try {
    await openSupport(destination);
    // Clicking through acknowledges the card; the permanent footer link stays.
    await call("support_prompt_never");
    supportCard.hidden = true;
    queueSupportCheck(null);
  } catch (err) {
    console.error(err);
    setStatus(`could not open the support page: ${String(err)}`);
  }
}

document.getElementById("support-coffee").onclick = () => followSupportLink("coffee");
document.getElementById("support-github").onclick = () => followSupportLink("github");

document.getElementById("support-later").onclick = async () => {
  try {
    const prompt = await call("support_prompt_later");
    supportCard.hidden = true;
    queueSupportCheck(prompt.next_at);
  } catch (err) {
    console.error(err);
    setStatus(`could not save that choice: ${String(err)}`);
  }
};

document.getElementById("support-never").onclick = async () => {
  try {
    await call("support_prompt_never");
    supportCard.hidden = true;
    queueSupportCheck(null);
  } catch (err) {
    console.error(err);
    setStatus(`could not save that choice: ${String(err)}`);
  }
};

// ---------------------------------------------------------------------------
// the journey
// ---------------------------------------------------------------------------

// Three steps, and the middle one decides what the third has to say. `intro` is
// dropped once it has been seen: a returning user still has to name a folder,
// but does not need the tiers explained again.
let journey = ["intro", "scope", "access"];
let step = "intro";
// Tracked separately from the journey, because it has to go false the moment the
// first scan starts. Otherwise `Scan folder…` would walk back through the access
// step for the rest of the session, having just been through it.
let firstRun = true;
// null means $HOME, which is also what the scanner reads a missing path as.
let chosenRoot = null;
// The access step opened from the panel rather than reached in order: same
// markup, but it ends in Done rather than in a scan.
let reviewing = false;
let gates = [];
let fullDisk = "granted";

const stepsNav = document.getElementById("steps");

function showStep(name) {
  step = name;
  reviewing = reviewing && name === "access";
  onboarding.hidden = false;
  onboarding.classList.toggle("review", reviewing);
  for (const section of onboarding.querySelectorAll(".step")) {
    section.hidden = section.dataset.step !== name;
  }

  stepsNav.hidden = reviewing;
  const dots = stepsNav.querySelector(".dots");
  dots.innerHTML = "";
  for (const each of journey) {
    const dot = document.createElement("i");
    dot.className = each === name ? "on" : "";
    dots.append(dot);
  }
  document.getElementById("step-back").disabled = journey.indexOf(name) <= 0;
}

document.getElementById("step-back").onclick = () => {
  const at = journey.indexOf(step);
  if (at > 0) showStep(journey[at - 1]);
};

document.querySelector('[data-go="scope"]').onclick = () => showStep("scope");

document.getElementById("scope-home").onclick = () => {
  chosenRoot = null;
  state.activeProfileId = null;
  offerAccess();
};

document.getElementById("home-scan-home").onclick = () => {
  chosenRoot = null;
  state.activeProfileId = null;
  hideHome();
  offerAccess();
};

document.getElementById("home-choose-folder").onclick = async () => {
  const picked = await chooseFolder();
  if (picked) {
    chosenRoot = picked;
    state.activeProfileId = null;
    hideHome();
    offerAccess();
  }
};

document.getElementById("scope-choose").onclick = async () => {
  const picked = await chooseFolder();
  if (picked) {
    chosenRoot = picked;
    state.activeProfileId = null;
    offerAccess();
  }
};

/**
 * Step three — or nothing at all.
 *
 * Skipped outright for a returning user whose gates under this root are all
 * granted: they answered this once, and asking again is the behaviour the whole
 * flow exists to remove. A first run always shows it, including when the answer
 * is "nothing needed" — a project directory costing no permissions is worth
 * seeing rather than inferring.
 */
async function offerAccess() {
  try {
    [gates, fullDisk] = await Promise.all([
      call("access_status", { root: chosenRoot }),
      call("full_disk_status"),
    ]);
  } catch (err) {
    // The scan is what the user asked for; a permissions screen we could not
    // build is not worth blocking it over.
    console.error(err);
    startScan();
    return;
  }

  const settled = gates.every((gate) => gate.state === "granted");
  if (settled && !firstRun) {
    startScan();
    return;
  }
  showStep("access");
  renderAccess();
}

const SUB = {
  unknown: "not requested",
  granted: "allowed",
  denied: "denied — macOS will not ask again",
};

function gateRow(gate) {
  const li = document.createElement("li");
  li.className = gate.state;
  li.title = gate.path;

  const what = document.createElement("div");
  what.className = "what";
  what.innerHTML = `<span class="name"></span><span class="sub"></span>`;
  what.querySelector(".name").textContent = gate.label;
  what.querySelector(".sub").textContent = SUB[gate.state] ?? gate.state;
  li.append(what);

  // A denied folder never prompts again, so a switch here would be a control
  // that does nothing. The row hands over to the pane that can still change it.
  if (gate.state === "denied") {
    const open = document.createElement("button");
    open.className = "ghost settings";
    open.textContent = "Open Settings ↗";
    open.onclick = () => call("open_privacy_settings", { pane: "files" }).catch(console.error);
    li.append(open);
  }

  const toggle = document.createElement("button");
  toggle.className = "toggle";
  toggle.setAttribute("role", "switch");
  toggle.setAttribute("aria-checked", String(gate.state === "granted"));
  toggle.setAttribute("aria-label", `Allow access to ${gate.label}`);
  toggle.disabled = gate.state === "denied";
  toggle.onclick = () => setGate(gate, gate.state !== "granted");
  li.append(toggle);
  return li;
}

async function setGate(gate, allow) {
  try {
    const updated = allow
      ? await call("request_access", { id: gate.id })
      : await call("revoke_access", { id: gate.id });
    gates = gates.map((each) => (each.id === updated.id ? updated : each));
    renderAccess();
  } catch (err) {
    onboardError.hidden = false;
    onboardError.textContent = String(err);
  }
}

function renderAccess() {
  const list = document.getElementById("gate-list");
  list.innerHTML = "";
  for (const gate of gates) list.append(gateRow(gate));

  // Not one of the three, and it must not look like one: there is no dialog to
  // raise, so it gets a way out rather than a switch.
  const fda = document.createElement("li");
  fda.className = `full-disk ${fullDisk}`;
  fda.innerHTML = `<div class="what"><span class="name"></span><span class="sub"></span></div>`;
  fda.querySelector(".name").textContent = "Everything else in ~/Library";
  fda.querySelector(".sub").textContent =
    fullDisk === "granted"
      ? "Full Disk Access is on"
      : "optional — Safari, Mail and similar need Full Disk Access";
  const open = document.createElement("button");
  open.className = "ghost settings";
  open.textContent = fullDisk === "granted" ? "Settings ↗" : "Open Settings ↗";
  open.onclick = () => call("open_privacy_settings", { pane: "full-disk" }).catch(console.error);
  fda.append(open);
  list.append(fda);

  const askable = gates.filter((gate) => gate.state === "unknown");
  const where = chosenRoot ? chosenRoot.split("/").pop() : "your home folder";

  document.getElementById("access-title").textContent = reviewing
    ? "Access"
    : gates.length === 0
      ? "Nothing to ask for"
      : "Folders macOS asks about";

  document.getElementById("access-lede").textContent =
    gates.length === 0
      ? `${where} holds none of the folders macOS gates, so this scan needs no permission at all.`
      : "macOS asks before an app reads these. Answer once and it stops asking.";

  document.getElementById("access-fineprint").textContent =
    "cachereaper only ever reads them. A folder you allow can be handed back " +
    "here later, which resets macOS to asking again.";

  const allow = document.getElementById("access-allow");
  allow.hidden = reviewing || askable.length === 0;
  allow.textContent =
    askable.length === 1 ? `Allow ${askable[0].label} and scan` : "Allow all and scan";

  document.getElementById("access-done").textContent = reviewing
    ? "Done"
    : askable.length
      ? "Scan without them"
      : "Scan now";
}

document.getElementById("access-allow").onclick = async (e) => {
  const button = e.currentTarget;
  button.disabled = true;
  // One at a time, deliberately. macOS queues its dialogs either way, and asking
  // in a fixed order is the difference between a moment the user is walked
  // through and three interruptions arriving from nowhere.
  for (const gate of gates.filter((each) => each.state === "unknown")) {
    await setGate(gate, true);
  }
  button.disabled = false;
  startScan();
};

document.getElementById("access-done").onclick = () => {
  if (reviewing) closeAccess();
  else startScan();
};

function closeAccess() {
  reviewing = false;
  onboarding.classList.remove("review");
  onboarding.hidden = true;
}

document.getElementById("review-access").onclick = async () => {
  reviewing = true;
  chosenRoot = state.rootPath || null;
  try {
    [gates, fullDisk] = await Promise.all([
      call("access_status", { root: chosenRoot }),
      call("full_disk_status"),
    ]);
  } catch (err) {
    console.error(err);
  }
  showStep("access");
  renderAccess();
};

async function startScan() {
  // Only after the journey has actually been walked, so a run that failed part
  // way through still explains itself next time.
  firstRun = false;
  call("set_seen_onboarding", { seen: true }).catch(() => {});
  runScan(chosenRoot ?? undefined);
}

let appConfig = null;

async function refreshProfiles() {
  try { appConfig = await call("config_get"); } catch (error) { console.error(error); return; }
  const select = document.getElementById("profile-selector");
  select.innerHTML = '<option value="">Profiles…</option>';
  for (const profile of appConfig.profiles || []) {
    const option = document.createElement("option"); option.value = profile.id; option.textContent = profile.name; select.append(option);
  }
  select.value = state.activeProfileId || "";
  renderHomeProfiles();
}

function renderHomeProfiles() {
  const holder = document.getElementById("home-profiles");
  holder.innerHTML = "";
  const profiles = appConfig?.profiles || [];
  if (!profiles.length) {
    const note = document.createElement("p");
    note.className = "home-empty";
    note.textContent = "Save a folder as a profile after scanning it.";
    holder.append(note);
    return;
  }
  for (const profile of profiles) {
    const button = document.createElement("button");
    button.className = "home-profile";
    button.innerHTML = "<span></span><small></small>";
    button.querySelector("span").textContent = profile.name;
    button.querySelector("small").textContent = profile.root;
    button.onclick = async () => {
      state.activeProfileId = profile.id;
      chosenRoot = null;
      hideHome();
      await runScan();
    };
    holder.append(button);
  }
}

document.getElementById("profile-selector").onchange = async (event) => {
  if (!event.target.value) return;
  state.activeProfileId = event.target.value;
  await runScan();
};

document.getElementById("save-profile").onclick = async () => {
  if (!state.rootPath) return;
  const name = window.prompt("Profile name");
  if (!name) return;
  try {
    const profile = await call("profile_create", { name, root: state.rootPath });
    state.activeProfileId = profile.id;
    await refreshProfiles();
  } catch (error) { window.alert(`Could not save profile: ${error}`); }
};

async function renderProfilesSheet() {
  await refreshProfiles();
  const referenceBody = document.getElementById("reference-roots-body");
  referenceBody.innerHTML = "";
  const referenceRoots = appConfig.reference_roots || [];
  if (!referenceRoots.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No reference roots. Add a master, archive, or backup folder to make it immutable.";
    referenceBody.append(empty);
  }
  for (const path of referenceRoots) {
    const row = document.createElement("p");
    const label = document.createElement("span");
    label.className = "path";
    label.textContent = path;
    const remove = document.createElement("button");
    remove.className = "ghost";
    remove.textContent = "Remove protection";
    remove.onclick = async () => {
      if (!window.confirm(`Remove immutable reference protection from ${path}? A fresh scan will be required.`)) return;
      await call("reference_remove", { path });
      await renderProfilesSheet();
      if (state.payload) runScan(state.rootPath);
    };
    row.append(label, " ", remove);
    referenceBody.append(row);
  }
  const body = document.getElementById("profiles-body"); body.innerHTML = "";
  let knownRules = new Set(state.findings.map((finding) => finding.rule_id));
  try { knownRules = new Set(await call("rule_ids")); } catch (_) { /* snapshot findings are the fallback */ }
  const section = (title, paths, rules, profileId = null) => {
    const article = document.createElement("article");
    const heading = document.createElement("h2"); heading.textContent = title; article.append(heading);
    for (const path of paths || []) {
      const row = document.createElement("p"); row.textContent = path;
      const remove = document.createElement("button"); remove.textContent = "Remove"; remove.className = "ghost";
      remove.onclick = async () => {
        if (!window.confirm(`Remove exclusion ${path} and rescan?`)) return;
        await call("exclusion_remove_path", { path, profileId });
        await renderProfilesSheet(); runScan(state.rootPath);
      };
      row.append(" ", remove); article.append(row);
    }
    for (const rule of rules || []) {
      const row = document.createElement("p"); row.textContent = `${rule.id}${rule.available ? "" : " (unavailable)"}`;
      const remove = document.createElement("button"); remove.textContent = "Remove"; remove.className = "ghost";
      remove.onclick = async () => {
        if (!window.confirm(`Suggest rule ${rule.id} again and rescan?`)) return;
        await call("exclusion_remove_rule", { ruleId: rule.id, profileId });
        await renderProfilesSheet(); runScan(state.rootPath);
      };
      row.append(" ", remove); article.append(row);
    }
    body.append(article);
  };
  const sections = exclusionSections(appConfig, knownRules);
  section(sections[0].title, sections[0].paths, sections[0].rules);
  for (const profile of appConfig.profiles || []) {
    const model = sections.find((value) => value.profileId === profile.id);
    section(model.title, model.paths, model.rules, profile.id);
    const rename = document.createElement("button"); rename.className = "ghost"; rename.textContent = "Rename";
    rename.onclick = async () => {
      const name = window.prompt("Profile name", profile.name);
      if (!name || name === profile.name) return;
      await call("profile_update", { id: profile.id, name, root: profile.root });
      renderProfilesSheet();
    };
    const remove = document.createElement("button"); remove.className = "danger"; remove.textContent = `Delete ${profile.name}`;
    remove.onclick = async () => {
      if (!window.confirm(`Delete profile “${profile.name}”? Global exclusions will not change.`)) return;
      await call("profile_delete", { id: profile.id });
      if (state.activeProfileId === profile.id) state.activeProfileId = null;
      renderProfilesSheet();
    };
    body.lastElementChild.append(rename, " ", remove);
  }
}

document.getElementById("manage-profiles").onclick = async () => {
  document.getElementById("profiles-sheet").hidden = false; await renderProfilesSheet();
};
document.getElementById("profiles-close").onclick = () => { document.getElementById("profiles-sheet").hidden = true; };
document.getElementById("reference-add").onclick = async () => {
  const path = await chooseFolder();
  if (!path || !window.confirm(`Protect ${path} as an immutable reference root? Files remain visible for duplicate comparison.`)) return;
  try {
    await call("reference_add", { path });
    await renderProfilesSheet();
    if (state.payload) runScan(state.rootPath);
  } catch (error) {
    window.alert(`Could not add reference root: ${error}`);
  }
};

async function renderHistory() {
  const body = document.getElementById("history-body"); body.textContent = "Loading…";
  try {
    const actions = await call("action_history_list"); body.innerHTML = "";
    if (!actions.length) { body.textContent = "No storage actions yet."; return; }
    for (const action of actions) {
      const article = document.createElement("article");
      article.innerHTML = `<strong></strong><p></p><details><summary>Action details</summary><div class="receipt-items"></div></details>`;
      article.querySelector("strong").textContent = `${action.action.replaceAll("-", " ")} · ${new Date(Number(action.at || 0)).toLocaleString()}`;
      const delta = action.actual_free_space_change == null ? "not measured" : `${action.actual_free_space_change >= 0 ? "+" : "−"}${human(Math.abs(action.actual_free_space_change))}`;
      article.querySelector("p").textContent = `${action.state} · ${human(action.estimated_bytes || 0)} · free-space delta ${delta} · ${action.recovery}${action.warning ? ` · ${action.warning}` : ""}`;
      const items = article.querySelector(".receipt-items");
      for (const item of action.items) { const p = document.createElement("p"); p.textContent = `${item.state}: ${item.path}${item.detail ? ` — ${item.detail}` : ""}`; items.append(p); }
      body.append(article);
    }
  } catch (error) { body.textContent = String(error); }
}
document.getElementById("open-history").onclick = () => { document.getElementById("history-sheet").hidden = false; renderHistory(); };
document.getElementById("history-close").onclick = () => { document.getElementById("history-sheet").hidden = true; };
document.getElementById("history-clear").onclick = async () => {
  if (!window.confirm("Clear completed cache-cleanup receipts? Quarantine and Trash recovery records will remain.")) return;
  await call("history_clear"); renderHistory();
};

async function renderQuarantineHistory() {
  const body = document.getElementById("quarantine-body");
  body.textContent = "Loading…";
  try {
    const [records, config] = await Promise.all([call("quarantine_history"), call("config_get")]);
    appConfig = config;
    const retention = document.getElementById("quarantine-retention");
    retention.querySelector('option[data-custom="true"]')?.remove();
    const retentionValue = config.quarantine_retention_days === null
      ? "never" : String(config.quarantine_retention_days);
    if (![...retention.options].some((option) => option.value === retentionValue)) {
      const custom = document.createElement("option");
      custom.value = retentionValue;
      custom.dataset.custom = "true";
      custom.textContent = `After ${retentionValue} days`;
      retention.append(custom);
    }
    retention.value = retentionValue;
    body.innerHTML = "";
    if (!records.length) {
      body.textContent = "No quarantined files.";
      return;
    }
    for (const record of records) {
      const article = document.createElement("article");
      const title = document.createElement("strong");
      title.textContent = record.state === "quarantined" ? "Recoverable file" :
        record.state === "recovery-required" ? "Recovery available" : record.state;
      const detail = document.createElement("p");
      const expiry = expiryPresentation(record, config.quarantine_retention_days);
      detail.textContent = `${human(record.logical_size)} · ${record.original_path}${expiry.message ? ` · ${expiry.message}` : ""}${record.reason ? ` · ${record.reason}` : ""}${record.parse_warning ? ` · ${record.parse_warning}` : ""}`;
      article.append(title, detail);
      if (record.state === "quarantined" || record.state === "recovery-required") {
        const restore = document.createElement("button");
        restore.className = "primary";
        restore.textContent = "Restore to original location";
        restore.onclick = async () => {
          restore.disabled = true;
          restore.textContent = "Restoring…";
          try {
            await call("quarantine_restore", { id: record.id });
            await renderQuarantineHistory();
          } catch (error) {
            window.alert(`Could not restore this file: ${error}`);
            restore.disabled = false;
            restore.textContent = "Restore to original location";
          }
        };
        article.append(restore);
      }
      if (expiry.eligible) {
        const expire = document.createElement("button");
        expire.className = "danger quarantine-expire";
        expire.textContent = "Permanently expire…";
        expire.onclick = async () => {
          const typed = window.prompt(
            `This permanently deletes the quarantined file. CacheReaper will rehash another copy first.\n\nType “${expiry.phrase}” to continue.`
          );
          if (typed !== expiry.phrase) return;
          expire.disabled = true;
          expire.textContent = "Revalidating…";
          try {
            await call("quarantine_expire", { id: record.id, confirmation: typed });
            await renderQuarantineHistory();
          } catch (error) {
            window.alert(`Could not permanently expire this file: ${error}`);
            expire.disabled = false;
            expire.textContent = "Permanently expire…";
          }
        };
        article.append(" ", expire);
      }
      body.append(article);
    }
  } catch (error) {
    body.textContent = String(error);
  }
}

document.getElementById("open-quarantine").onclick = () => {
  document.getElementById("quarantine-sheet").hidden = false;
  renderQuarantineHistory();
};
document.getElementById("quarantine-close").onclick = () => {
  document.getElementById("quarantine-sheet").hidden = true;
};
document.getElementById("quarantine-retention").onchange = async (event) => {
  const days = event.target.value === "never" ? null : Number(event.target.value);
  try {
    appConfig = await call("quarantine_retention_set", { days });
    await renderQuarantineHistory();
  } catch (error) {
    window.alert(`Could not save retention policy: ${error}`);
    await renderQuarantineHistory();
  }
};

document.getElementById("choose").onclick = async () => {
  const picked = await chooseFolder();
  if (picked) {
    chosenRoot = picked;
    state.activeProfileId = null;
    hideHome();
    offerAccess();
  }
};

document.getElementById("home-button").onclick = () => showHome();

async function boot() {
  let config = { seen_onboarding: false };
  try {
    config = await call("config_get");
  } catch (err) {
    console.error(err);
  }
  firstRun = !config.seen_onboarding;
  appConfig = config;
  // This begins the update check immediately after the application has opened,
  // before profile loading or a possible scan can delay it.
  initUpdates(config);
  if ((config.profiles || []).some((profile) => profile.id === config.last_profile_id)) {
    state.activeProfileId = config.last_profile_id;
  }
  await refreshProfiles();
  // The home page is the entry point for every launch. The retained access
  // sheet appears only after a concrete scan scope has been chosen.
  journey = ["scope", "access"];
  showHome();
  initSupport();
}

if (inTauri) {
  boot();
} else {
  // Browser dev mode reads a snapshot scanned ahead of time by dev.sh, so there
  // is no scanner to point at a different folder.
  for (const id of ["choose", "scope-choose"]) {
    const button = document.getElementById(id);
    button.disabled = true;
    button.title = "Choosing a folder needs the desktop app — pass a path to ./gui/dev.sh instead";
  }

  // ./gui/dev.sh is for working on the map, so it opens straight into one.
  // Add ?onboarding to the URL to work on the journey instead, against the
  // stubbed gates above.
  if (new URLSearchParams(location.search).has("onboarding")) {
    boot();
  } else {
    runScan();
    // The panel is on screen in this mode without boot() ever running, and the
    // version line lives in the panel.
    initUpdates({ auto_update: true });
    initSupport();
  }
}
