// cachereaper treemap.
//
// Runs in two modes:
//   * inside Tauri  -> talks to the Rust core over IPC
//   * plain browser -> loads snapshot.json, produced by
//                      `cargo run --release --bin snapshot -- tree ~ gui/dist/snapshot.json`
// The second mode is what makes the UI developable and screenshot-testable
// without building the desktop shell.

import { squarify, human } from "./treemap.js";

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

async function load(path) {
  if (inTauri) {
    const { invoke } = window.__TAURI__.core;
    if (!progressBound) {
      const { listen } = window.__TAURI__.event;
      await listen("scan-progress", (e) => {
        const { files, bytes } = e.payload;
        setStatus(`scanning… ${files.toLocaleString()} files, ${human(bytes)}`);
        setScanProgress(files, bytes);
      });
      progressBound = true;
    }
    return invoke("scan_home", { path: path ?? null });
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
  return {
    config_get: async () => ({
      seen_onboarding: false,
      access: {},
      auto_update: true,
      support_prompt_at: null,
      support_prompt_disabled: false,
    }),
    access_status: async () => gates.map((g) => ({ ...g })),
    full_disk_status: async () => "denied",
    request_access: async ({ id }) => settle(id, "granted"),
    revoke_access: async ({ id }) => settle(id, "unknown"),
    open_privacy_settings: async () => {},
    set_seen_onboarding: async () => {},
    reveal: async () => {},
    app_version: async () => "1.4.0-dev",
    set_auto_update: async () => {},
    update_check: async () =>
      pretendBehind
        ? { version: "9.9.9", current: "1.4.0-dev", notes: "A pretend release, for working on this card." }
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
function setScanProgress(files, bytes) {
  document.getElementById("scan-counts").textContent =
    `${files.toLocaleString()} files · ${human(bytes)}`;
}

// ---------------------------------------------------------------------------
// tree helpers
// ---------------------------------------------------------------------------

const nameOf = (i) => state.nodes[i].n;
const sizeOf = (i) => state.nodes[i].s;
const ruleOf = (i) => state.nodes[i].r || null;

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

function render() {
  renderChrome();
  renderFindings();
  renderSelection();
  draw();
}

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

function openMenu(x, y, path) {
  menuEl.dataset.path = path;
  menuEl.querySelector(".path").textContent = path;
  menuEl.hidden = false;
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
  openMenu(e.clientX, e.clientY, pathOf(cell.index));
});

menuEl.querySelector('[data-action="reveal"]').onclick = () => {
  const path = menuEl.dataset.path;
  closeMenu();
  if (path) revealPath(path);
};

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
  state.current = 0;
  state.selected.clear();
  state.hover = -1;
  state.drag = null;

  document.getElementById("total").textContent = human(data.stats.bytes);

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
  scanning = true;
  document.body.classList.add("busy");
  onboardError.hidden = true;

  document.getElementById("scan-path").textContent = path || "your home folder";
  document.getElementById("scan-counts").textContent = "counting…";
  scanningEl.hidden = false;

  setStatus("scanning…");
  try {
    applyPayload(await load(path));
    onboarding.hidden = true;
  } catch (err) {
    // Come back to the journey if we never got a tree: an empty map with the
    // sheet gone is a dead end.
    setStatus(null);
    showStep("scope");
    onboardError.hidden = false;
    onboardError.textContent = String(err);
    console.error(err);
  } finally {
    scanning = false;
    scanningEl.hidden = true;
    document.body.classList.remove("busy");
  }
}

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
const updateStatusEl = document.getElementById("update-status");
const updateLook = document.getElementById("update-look");
const updateAuto = document.getElementById("update-auto");
const updateInstall = document.getElementById("update-install");

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

document.getElementById("update-later").onclick = () => {
  // For this session only. A build worth telling you about once is worth
  // telling you about again next launch, and a setting to silence one specific
  // version is a setting that has to be got right forever.
  updateCard.hidden = true;
};

updateAuto.onchange = async () => {
  try {
    await call("set_auto_update", { on: updateAuto.checked });
  } catch (err) {
    console.error(err);
    updateAuto.checked = !updateAuto.checked;
    updateSays("Could not save that setting.");
  }
};

updateInstall.onclick = async () => {
  if (installing) return;
  installing = true;
  updateInstall.disabled = true;
  updateInstall.textContent = "Downloading…";

  try {
    if (inTauri && !updateProgressBound) {
      const { listen } = window.__TAURI__.event;
      await listen("update-progress", ({ payload }) => {
        // The manifest carries a length for both platforms, but a proxy that
        // strips it would otherwise leave the button reading "NaN%".
        updateInstall.textContent = payload.total
          ? `Downloading ${Math.round((payload.downloaded / payload.total) * 100)}%`
          : `Downloading ${human(payload.downloaded)}`;
      });
      updateProgressBound = true;
    }
    // On success this never returns: the app is replaced and restarted.
    await call("update_install");
  } catch (err) {
    console.error(err);
    installing = false;
    updateInstall.disabled = false;
    updateInstall.textContent = "Install and restart";
    updateSays(`Update failed: ${err}`);
  }
};

/** Version line, the switch, and — if the switch is on — the launch check. */
async function initUpdates(config) {
  updateAuto.checked = config.auto_update !== false;
  try {
    document.getElementById("app-version").textContent = `cachereaper ${await call("app_version")}`;
  } catch (err) {
    console.error(err);
  }
  if (updateAuto.checked) lookForUpdate(false);
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
  offerAccess();
};

document.getElementById("scope-choose").onclick = async () => {
  const picked = await chooseFolder();
  if (picked) {
    chosenRoot = picked;
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

document.getElementById("choose").onclick = async () => {
  const picked = await chooseFolder();
  if (picked) {
    chosenRoot = picked;
    offerAccess();
  }
};

async function boot() {
  let config = { seen_onboarding: false };
  try {
    config = await call("config_get");
  } catch (err) {
    console.error(err);
  }
  firstRun = !config.seen_onboarding;
  journey = config.seen_onboarding ? ["scope", "access"] : ["intro", "scope", "access"];
  showStep(journey[0]);
  // Deliberately not awaited: the launch check is a network round trip, and the
  // folder step should be on screen before it, not after it.
  initUpdates(config);
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
