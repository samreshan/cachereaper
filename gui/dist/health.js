export function healthWarnings(stats = {}) {
  const warnings = [];
  if ((stats.unreadable || 0) > 0 || (stats.excluded || 0) > 0) {
    warnings.push("Coverage is partial: unreadable and excluded directories were not measured.");
  }
  if (stats.volume_capacity != null && stats.reclaimable_bytes > stats.volume_capacity) {
    warnings.push("Reclaimable bytes exceed this volume’s capacity. Filesystem accounting may be inconsistent.");
  }
  if (stats.reclaimable_bytes > stats.allocated_reference_bytes && stats.allocated_reference_bytes != null) {
    warnings.push("Reclaimable bytes exceed allocated-reference bytes.");
  }
  return warnings;
}

export function redactPath(path, home) {
  const value = String(path || "");
  if (!home) return value;
  return value === home ? "~" : value.startsWith(`${home}/`) || value.startsWith(`${home}\\`)
    ? `~${value.slice(home.length)}` : value;
}

export function diagnostics(payload, { home = "", platform = "unknown", version = "unknown" } = {}) {
  const stats = payload.stats || {};
  const lines = [
    `CacheReaper ${version} diagnostics`,
    `Platform: ${platform}`,
    `Root: ${redactPath(payload.root_path, home)}`,
    `Reclaimable bytes: ${stats.reclaimable_bytes ?? stats.bytes ?? 0}`,
    `Allocated-reference bytes: ${stats.allocated_reference_bytes ?? "unavailable"}`,
    `Logical bytes: ${stats.logical_bytes ?? "unavailable"}`,
    `Shared/snapshot bytes: ${stats.shared_or_snapshot_bytes ?? "unavailable"}`,
    `Volume capacity: ${stats.volume_capacity ?? "unavailable"}`,
    `Volume free: ${stats.volume_free ?? "unavailable"}`,
    `Files/directories: ${stats.files ?? 0}/${stats.dirs ?? 0}`,
    `Unreadable/user-excluded directories: ${stats.unreadable ?? 0}/${stats.excluded ?? 0}`,
    `Elapsed ms: ${stats.elapsed_ms ?? 0}`,
  ];
  // Boundaries only: never include filenames beneath unreadable/excluded roots.
  for (const path of [...(stats.unreadable_paths || []), ...(stats.excluded_paths || [])].slice(0, 20)) {
    lines.push(`Boundary: ${redactPath(path, home)}`);
  }
  lines.push(...healthWarnings(stats).map((warning) => `Warning: ${warning}`));
  return lines.join("\n");
}
