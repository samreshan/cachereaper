// Squarified treemap layout (Bruls, Huizing & van Wijk, 2000).
//
// Kept free of DOM and canvas references so it can be unit-tested with plain
// node: `node gui/tests/treemap.test.mjs`.

/**
 * Worst (largest) aspect ratio in a row of already-scaled areas.
 * @param {number[]} areas scaled pixel areas
 * @param {number} side length of the side the row is laid along
 */
function worstRatio(areas, side) {
  if (!areas.length) return Infinity;
  let sum = 0;
  let max = -Infinity;
  let min = Infinity;
  for (const a of areas) {
    sum += a;
    if (a > max) max = a;
    if (a < min) min = a;
  }
  if (sum <= 0 || min <= 0) return Infinity;
  const s2 = sum * sum;
  const side2 = side * side;
  return Math.max((side2 * max) / s2, s2 / (side2 * min));
}

/**
 * Lay children out inside a rectangle, largest first.
 *
 * @param {{value:number}[]} items  anything with a numeric `value`
 * @param {{x:number,y:number,w:number,h:number}} rect
 * @returns {{item:object,x:number,y:number,w:number,h:number}[]}
 */
export function squarify(items, rect) {
  const out = [];
  if (!items || rect.w <= 0 || rect.h <= 0) return out;

  const queue = items.filter((i) => i.value > 0).sort((a, b) => b.value - a.value);
  if (!queue.length) return out;

  const total = queue.reduce((s, i) => s + i.value, 0);
  // pixels per unit of value; constant for the whole layout, because each row
  // consumes exactly the area its values are worth
  const scale = (rect.w * rect.h) / total;
  const scaled = queue.map((i) => i.value * scale);

  let r = { x: rect.x, y: rect.y, w: rect.w, h: rect.h };
  let i = 0;

  while (i < queue.length) {
    const side = Math.min(r.w, r.h);
    let end = i + 1;
    let best = worstRatio(scaled.slice(i, end), side);

    // grow the row while the worst aspect ratio keeps improving
    while (end < queue.length) {
      const candidate = worstRatio(scaled.slice(i, end + 1), side);
      if (candidate > best) break;
      best = candidate;
      end += 1;
    }

    const rowArea = scaled.slice(i, end).reduce((s, a) => s + a, 0);

    if (r.w >= r.h) {
      const colWidth = rowArea / r.h;
      let y = r.y;
      for (let k = i; k < end; k += 1) {
        const h = scaled[k] / colWidth;
        out.push({ item: queue[k], x: r.x, y, w: colWidth, h });
        y += h;
      }
      r = { x: r.x + colWidth, y: r.y, w: r.w - colWidth, h: r.h };
    } else {
      const rowHeight = rowArea / r.w;
      let x = r.x;
      for (let k = i; k < end; k += 1) {
        const w = scaled[k] / rowHeight;
        out.push({ item: queue[k], x, y: r.y, w, h: rowHeight });
        x += w;
      }
      r = { x: r.x, y: r.y + rowHeight, w: r.w, h: r.h - rowHeight };
    }
    i = end;
  }

  return out;
}

/** Bytes as a short human string, matching the CLI's formatting. */
export function human(bytes) {
  const units = ["B", "K", "M", "G", "T"];
  let value = bytes;
  for (let i = 0; i < units.length; i += 1) {
    if (Math.abs(value) < 1024 || i === units.length - 1) {
      return units[i] === "B" ? `${Math.round(value)}B` : `${value.toFixed(1)}${units[i]}`;
    }
    value /= 1024;
  }
  return `${value.toFixed(1)}T`;
}
