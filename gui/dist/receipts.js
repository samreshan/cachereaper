export function signedBytes(value, human) {
  if (value == null) return "unavailable";
  const sign = value > 0 ? "+" : value < 0 ? "−" : "±";
  return `${sign}${human(Math.abs(value))}`;
}

export function receiptPresentation(receipt, human) {
  const summary = receipt.summary || {};
  const removed = receipt.items.filter((item) => item.status === "removed").length;
  const skipped = receipt.items.filter((item) => item.status === "skipped").length;
  return {
    title: new Date(Number(receipt.started_at || 0)).toLocaleString(),
    status: receipt.legacy ? "Legacy receipt" : receipt.complete ? "Complete" : "Incomplete",
    estimated: human(summary.estimated_removed_bytes ?? receipt.estimated_bytes ?? 0),
    delta: signedBytes(summary.signed_free_space_change, human),
    counts: `${removed} removed · ${skipped} skipped`,
  };
}
