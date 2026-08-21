export function isCurrentScanEvent(activeScanId, payload) {
  return Boolean(activeScanId) && payload?.scan_id === activeScanId;
}

export function cancelViewState(requested, finished = false) {
  if (finished) return { label: "Cancel", disabled: false };
  return requested ? { label: "Stopping…", disabled: true } : { label: "Cancel", disabled: false };
}
