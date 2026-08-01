// Layout tests. Run: node gui/tests/treemap.test.mjs
import { squarify, human } from "../dist/treemap.js";

let failures = 0;
let checks = 0;

function ok(cond, label) {
  checks += 1;
  if (!cond) {
    failures += 1;
    console.error(`  FAIL  ${label}`);
  }
}

function close(a, b, tol, label) {
  ok(Math.abs(a - b) <= tol, `${label} (${a} vs ${b}, tol ${tol})`);
}

const RECT = { x: 0, y: 0, w: 800, h: 600 };

// --- areas are proportional to values ---------------------------------------
{
  const items = [
    { name: "a", value: 50 },
    { name: "b", value: 30 },
    { name: "c", value: 20 },
  ];
  const laid = squarify(items, RECT);
  ok(laid.length === 3, "every item is placed");

  const totalArea = RECT.w * RECT.h;
  for (const cell of laid) {
    const expected = (cell.item.value / 100) * totalArea;
    close(cell.w * cell.h, expected, expected * 0.001, `area of ${cell.item.name}`);
  }

  const sum = laid.reduce((s, c) => s + c.w * c.h, 0);
  close(sum, totalArea, totalArea * 0.001, "cells fill the rectangle exactly");
}

// --- cells never overlap -----------------------------------------------------
{
  const items = Array.from({ length: 40 }, (_, i) => ({ name: `n${i}`, value: (i % 7) + 1 }));
  const laid = squarify(items, RECT);
  let overlaps = 0;
  for (let i = 0; i < laid.length; i += 1) {
    for (let j = i + 1; j < laid.length; j += 1) {
      const a = laid[i];
      const b = laid[j];
      const separated =
        a.x + a.w <= b.x + 1e-6 ||
        b.x + b.w <= a.x + 1e-6 ||
        a.y + a.h <= b.y + 1e-6 ||
        b.y + b.h <= a.y + 1e-6;
      if (!separated) overlaps += 1;
    }
  }
  ok(overlaps === 0, `no overlapping cells (found ${overlaps})`);

  for (const c of laid) {
    ok(
      c.x >= -1e-6 && c.y >= -1e-6 && c.x + c.w <= RECT.w + 1e-6 && c.y + c.h <= RECT.h + 1e-6,
      `cell ${c.item.name} stays inside the rectangle`
    );
  }
}

// --- squarified really is squarer than slice-and-dice ------------------------
{
  const items = Array.from({ length: 24 }, (_, i) => ({ name: `n${i}`, value: 24 - i }));
  const laid = squarify(items, RECT);
  const ratios = laid.map((c) => Math.max(c.w / c.h, c.h / c.w));
  const worst = Math.max(...ratios);
  ok(worst < 6, `worst aspect ratio stays reasonable (got ${worst.toFixed(2)})`);

  // naive slice-and-dice for comparison
  const total = items.reduce((s, i) => s + i.value, 0);
  let x = 0;
  let sliceWorst = 0;
  for (const item of items) {
    const w = (item.value / total) * RECT.w;
    sliceWorst = Math.max(sliceWorst, Math.max(w / RECT.h, RECT.h / w));
    x += w;
  }
  ok(worst < sliceWorst, `beats slice-and-dice (${worst.toFixed(1)} < ${sliceWorst.toFixed(1)})`);
}

// --- degenerate input --------------------------------------------------------
{
  ok(squarify([], RECT).length === 0, "empty input yields no cells");
  ok(squarify([{ value: 0 }], RECT).length === 0, "zero-valued items are dropped");
  ok(squarify([{ value: 5 }], { x: 0, y: 0, w: 0, h: 10 }).length === 0, "zero-width rect");
  const single = squarify([{ name: "solo", value: 7 }], RECT);
  ok(single.length === 1, "single item is placed");
  close(single[0].w, RECT.w, 1e-6, "single item spans the full width");
  close(single[0].h, RECT.h, 1e-6, "single item spans the full height");
}

// --- ordering ----------------------------------------------------------------
{
  const laid = squarify(
    [
      { name: "small", value: 1 },
      { name: "big", value: 99 },
    ],
    RECT
  );
  ok(laid[0].item.name === "big", "largest item is laid out first");
}

// --- human() matches the CLI -------------------------------------------------
{
  ok(human(0) === "0B", "human(0)");
  ok(human(1536) === "1.5K", "human(1536)");
  ok(human(5 * 1024 ** 3) === "5.0G", "human(5G)");
}

console.log(`${checks - failures}/${checks} checks passed`);
if (failures) {
  console.error(`${failures} FAILED`);
  process.exit(1);
}
