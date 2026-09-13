export const MODE_DETAILS = Object.freeze({
  cache: {
    label: "Cache Scan",
    summary: "Directory metadata and rule markers only. File contents are not read.",
  },
  whole: {
    label: "Whole Disk",
    summary: "File metadata is categorized locally. File contents are not read.",
  },
  all: {
    label: "All Files",
    summary: "Candidate files with matching sizes are fully hashed locally to prove exact duplicates.",
  },
});

export function normalizeMode(mode) {
  return Object.hasOwn(MODE_DETAILS, mode) ? mode : "cache";
}

export function analysisMetrics(analysis = {}) {
  const groups = Array.isArray(analysis.duplicate_groups) ? analysis.duplicate_groups : [];
  return {
    inventoryFiles: Number(analysis.inventory_files) || 0,
    categoryCount: Array.isArray(analysis.categories) ? analysis.categories.length : 0,
    duplicateGroups: groups.length,
    duplicateFiles: groups.reduce((sum, group) => sum + (group.files?.length || 0), 0),
    duplicateBytes: Number(analysis.duplicate_reclaimable_bytes) || 0,
    complete: analysis.content_analysis_complete === true,
  };
}

export function visibleFileRows(files, limit = 25) {
  if (!Array.isArray(files)) return [];
  return files.slice(0, Math.max(0, limit));
}

export function advancedMetrics(payload = {}) {
  const media = payload.media || {};
  const intelligence = payload.intelligence || {};
  const ownership = Array.isArray(intelligence.ownership) ? intelligence.ownership : [];
  return {
    similarGroups: Array.isArray(media.groups) ? media.groups.length : 0,
    similarFiles: Array.isArray(media.groups)
      ? media.groups.reduce((sum, group) => sum + (group.files?.length || 0), 0)
      : 0,
    possibleLeftovers: ownership.filter((item) => item.state === "possible-leftover").length,
    projects: Array.isArray(intelligence.projects) ? intelligence.projects.length : 0,
    anomalies: Array.isArray(intelligence.forecast?.anomalies) ? intelligence.forecast.anomalies.length : 0,
  };
}

export function formatDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  if (value < 60) return `${Math.round(value)} sec`;
  if (value < 3600) return `${Math.round(value / 60)} min`;
  return `${(value / 3600).toFixed(value < 36_000 ? 1 : 0)} hr`;
}

export function ownershipStateLabel(state) {
  return ({
    "installed-match": "Installed match",
    "possible-leftover": "Possible leftover",
    unresolved: "Unresolved",
  })[state] || "Unresolved";
}

export function offloadSummary(status = {}) {
  const providers = Array.isArray(status.configured_providers) ? status.configured_providers : [];
  if (!status.compiled) return "Optional connectors are disabled in this build. Nothing can leave this device.";
  if (!providers.length) return "The consent-gated connector boundary is enabled, but no provider is configured. Nothing can leave this device.";
  return `${providers.length} provider${providers.length === 1 ? "" : "s"} available. Every transfer requires an itemized disclosure and exact confirmation.`;
}
