export const PAGE_SIZE = 250;

const tierRank = { low: 0, medium: 1, high: 2 };

export function filterSortFindings(findings, options = {}) {
  const query = String(options.query || "").trim().toLocaleLowerCase();
  const tiers = new Set(options.tiers || ["low", "medium", "high"]);
  const excluded = options.excluded || "hide";
  const sort = options.sort || "size";
  const direction = options.direction === "asc" ? 1 : -1;
  const rows = findings.filter((finding) => {
    if (!tiers.has(finding.tier)) return false;
    if (excluded === "hide" && finding.excluded) return false;
    if (excluded === "only" && !finding.excluded) return false;
    if (!query) return true;
    return [finding.path, finding.rule_id, finding.label]
      .some((value) => String(value || "").toLocaleLowerCase().includes(query));
  });
  return rows
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => {
      const a = left.finding;
      const b = right.finding;
      let compared = 0;
      if (sort === "size") compared = a.reclaimable_size - b.reclaimable_size;
      else if (sort === "age") compared = (b.mtime || 0) - (a.mtime || 0);
      else if (sort === "tier") compared = tierRank[a.tier] - tierRank[b.tier];
      else compared = String(a[sort === "rule" ? "rule_id" : "path"] || "")
        .localeCompare(String(b[sort === "rule" ? "rule_id" : "path"] || ""));
      if (compared) return compared * direction;
      const nodeCompared = Number(a.node_id) - Number(b.node_id);
      return nodeCompared || left.index - right.index;
    })
    .map(({ finding }) => finding);
}

export function visibleBatch(findings, pages = 1) {
  return findings.slice(0, Math.max(1, pages) * PAGE_SIZE);
}

export function ageDays(mtime, now = Date.now() / 1000) {
  return Math.max(0, (now - Number(mtime || 0)) / 86400);
}
