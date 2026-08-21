import fs from "node:fs";
import { filterSortFindings, visibleBatch } from "../dist/findings.js";
import { diagnostics, healthWarnings, redactPath } from "../dist/health.js";
import { receiptPresentation, signedBytes } from "../dist/receipts.js";
import { cancelViewState, isCurrentScanEvent } from "../dist/lifecycle.js";
import { exclusionSections } from "../dist/profiles.js";
import { human } from "../dist/treemap.js";

let checks = 0;
let failures = 0;
function ok(value, label) { checks += 1; if (!value) { failures += 1; console.error(`  FAIL  ${label}`); } }

const findings = Array.from({ length: 300 }, (_, node_id) => ({
  node_id, path: `/root/${node_id % 2 ? "Cache" : "build"}/${node_id}`,
  rule_id: node_id % 2 ? "npm-cache" : "rust-target", label: node_id % 2 ? "NPM content" : "Rust output",
  tier: node_id % 3 === 0 ? "medium" : "low", reclaimable_size: node_id % 4, mtime: node_id,
}));
const searched = filterSortFindings(findings, { query: "NPM", tiers: ["low", "medium"], sort: "size" });
ok(searched.length === 150, "searches label case-insensitively");
ok(searched.every((row, index, rows) => index === 0 || rows[index - 1].reclaimable_size >= row.reclaimable_size), "size descending by default");
const tied = filterSortFindings(findings.slice(0, 8), { sort: "size" }).filter((row) => row.reclaimable_size === 3);
ok(tied[0].node_id < tied[1].node_id, "node id breaks equal-sort ties stably");
ok(visibleBatch(findings).length === 250 && visibleBatch(findings, 2).length === 300, "batches 250 rows");

ok(redactPath("/Users/sam/cache", "/Users/sam") === "~/cache", "redacts home path");
const report = diagnostics({ root_path: "/Users/sam", stats: { unreadable_paths: ["/Users/sam/private"], files: 2 } }, { home: "/Users/sam" });
ok(report.includes("Boundary: ~/private") && !report.includes("/Users/sam/private"), "diagnostics redact boundaries");
ok(healthWarnings({ reclaimable_bytes: 200, allocated_reference_bytes: 100, volume_capacity: 150 }).length === 2, "impossible accounting is explicit");

ok(signedBytes(-1024, human) === "−1.0K", "negative disk delta stays signed");
const receipt = receiptPresentation({ started_at: 1, legacy: true, complete: false, estimated_bytes: 10, items: [{ status: "removed" }] }, human);
ok(receipt.status === "Legacy receipt" && receipt.counts.includes("1 removed"), "legacy receipt presentation");
ok(isCurrentScanEvent("new", { scan_id: "new" }) && !isCurrentScanEvent("new", { scan_id: "old" }), "rejects stale progress events");
ok(cancelViewState(true).disabled && cancelViewState(true).label === "Stopping…", "cancel enters stopping state");
const sections = exclusionSections({ global_excluded_rules: ["known", "future"], profiles: [] }, new Set(["known"]));
ok(sections[0].rules[0].available && !sections[0].rules[1].available, "unknown saved rules remain visible as unavailable");

const html = fs.readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
for (const id of ["view-mode", "finding-search", "finding-table", "scan-health", "copy-diagnostics", "cancel-scan", "profile-selector", "profiles-sheet", "history-sheet", "home", "home-scan-home", "home-choose-folder", "home-update"]) {
  ok(html.includes(`id="${id}"`), `required DOM id ${id}`);
}

console.log(`${checks - failures}/${checks} checks passed`);
if (failures) process.exit(1);
