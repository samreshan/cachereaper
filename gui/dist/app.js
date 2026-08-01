// cachereap treemap.
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
const GAP = 1; // px between sibling blocks

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
const TIER_HSL = {
  low: [148, 46, 44],
  medium: [40, 68, 48],
  high: [4, 60, 52],
};

const isDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

const inTauri = typeof window !== "undefined" && !!window.__TAURI__;

async function load() {
  if (inTauri) {
    const { invoke } = window.__TAURI__.core;
    const { listen } = window.__TAURI__.event;
    await listen("scan-progress", (e) => {
      const { files, bytes } = e.payload;
      setStatus(`scanning… ${files.toLocaleString()} files, ${human(bytes)}`);
    });
    return invoke("scan_home");
  }
  const res = await fetch("snapshot.json");
  if (!res.ok) throw new Error(`snapshot.json missing (${res.status})`);
  return res.json();
}

function setStatus(text) {
  if (text === null) {
    statusEl.hidden = true;
    return;
  }
  statusEl.hidden = false;
  statusEl.textContent = text;
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
      drawNode(item.node, inset(cell), depth + 1);
    } else {
      const owner = item.kind === "child" ? item.node : index;
      paintLeaf(owner, cell, depth + 1, item.kind === "rest" ? item.count : 0, item.kind);
    }
  }
}

/** A small uniform gutter is what makes the map read as soft rather than dense. */
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
  roundRect(rect.x, rect.y, rect.w, rect.h, 2);
  ctx.fillStyle = hsl(base);
  ctx.fill();

  if (rect.w > 3 && rect.h > 3) {
    ctx.strokeStyle = isDark() ? "rgba(0,0,0,0.35)" : "rgba(0,0,0,0.13)";
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
    roundRect(rect.x + 3, rect.y + 2, rect.w - 6, rect.h - 4, 2);
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
    roundRect(cell.x, cell.y, cell.w, cell.h, 2);
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
    roundRect(b.x0 - 1, b.y0 - 1, b.x1 - b.x0 + 2, b.y1 - b.y0 + 2, 2);
    ctx.stroke();
  }
  ctx.restore();
}

function drawHover() {
  if (state.hover < 0) return;
  const cell = state.cells.find((c) => c.index === state.hover);
  if (!cell) return;
  ctx.save();
  roundRect(cell.x, cell.y, cell.w, cell.h, 2);
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
      <span class="count">${g.nodes.length > 1 ? `×${g.nodes.length}` : ""}</span>`;
    li.title = g.regen ? `restore: ${g.regen}` : "";
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
      `cachereap cannot tell you how to get them back, and they may not be caches at all.`;
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
  tooltip.innerHTML =
    `<div class="path">${pathOf(index)}</div>` +
    `<div class="meta">${human(node.s)} · ${node.f.toLocaleString()} files` +
    (age !== null ? ` · ${age}d old` : "") +
    (node.r ? ` · <strong>${node.r}</strong> (${node.t})` : " · unclassified") +
    `</div>` +
    (node.g ? `<div class="regen">restore: ${node.g}</div>` : "");
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
  if (e.key === "Backspace" || e.key === "ArrowUp") {
    if (state.current !== 0) {
      state.current = state.nodes[state.current].p;
      render();
      e.preventDefault();
    }
  } else if (e.key === "Escape") {
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
  const { invoke } = window.__TAURI__.core;
  const result = await invoke("delete_targets", { targets });
  window.alert(`Freed ${human(result.freed)} across ${result.removed} paths.`);
  location.reload();
};

window.addEventListener("resize", resize);

// Debug/test hook: lets browser-driven UI checks assert on internal state and
// exercise selection through the real code path rather than poking the Set.
window.__cachereap = state;
window.__cachereap.api = { addSelection, toggleSelection, collapseToFolders, covers, render };

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

load()
  .then((data) => {
    state.nodes = data.nodes;
    state.rootPath = data.root_path;
    state.stats = data.stats;
    document.getElementById("total").textContent = human(data.stats.bytes);
    if (data.stats.unreadable > 0) {
      const warn = document.getElementById("warning");
      warn.hidden = false;
      warn.textContent =
        `${data.stats.unreadable} directories could not be read, so their contents are ` +
        `not counted. Grant Full Disk Access to include them.`;
    }
    setStatus(
      `${data.stats.files.toLocaleString()} files · ${data.stats.dirs.toLocaleString()} dirs · ` +
        `${(data.stats.elapsed_ms / 1000).toFixed(1)}s`
    );
    resize();
    render();
  })
  .catch((err) => {
    setStatus(`failed: ${err.message}`);
    console.error(err);
  });
