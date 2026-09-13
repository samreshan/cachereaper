export const TARGET_UNITS = Object.freeze({ MB: 2 ** 20, GB: 2 ** 30, TB: 2 ** 40 });

export function targetBytes(value, unit = "GB") {
  const numeric = Number(value);
  const multiplier = TARGET_UNITS[unit];
  if (!Number.isFinite(numeric) || numeric <= 0 || !multiplier) return 0;
  const bytes = numeric * multiplier;
  return Number.isSafeInteger(bytes) ? bytes : 0;
}

export function clauseLabel(clause) {
  const fields = { size: "size", "age-days": "age", category: "category", path: "path", risk: "risk", kind: "kind", recoverability: "recovery", provenance: "source" };
  const operators = { "greater-than": ">", "greater-than-or-equal": "≥", "less-than": "<", "less-than-or-equal": "≤", equal: "is", contains: "contains" };
  const value = clause?.value?.value;
  return `${fields[clause?.field] || clause?.field} ${operators[clause?.operator] || clause?.operator} ${value}`;
}

export function planSummary(plan, human) {
  const count = plan?.actions?.length || 0;
  const target = plan?.target_met ? "Target met" : "Target not met";
  return `${target} · ${count} action${count === 1 ? "" : "s"} · ${human(plan?.estimated_reclaimable_bytes || 0)} potential · ${human(plan?.immediate_reclaimable_bytes || 0)} immediate`;
}

export function sortedInsights(insights) {
  return [...(insights || [])].sort((a, b) =>
    (b.estimated_reclaimable_bytes || 0) - (a.estimated_reclaimable_bytes || 0) || a.id.localeCompare(b.id)
  );
}
