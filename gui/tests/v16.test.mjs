import fs from "node:fs";
import { filterSortFindings, visibleBatch } from "../dist/findings.js";
import { diagnostics, healthWarnings, redactPath } from "../dist/health.js";
import { receiptPresentation, signedBytes } from "../dist/receipts.js";
import { cancelViewState, isCurrentScanEvent } from "../dist/lifecycle.js";
import { exclusionSections, referenceRootFor } from "../dist/profiles.js";
import { human } from "../dist/treemap.js";
import {
  advancedMetrics,
  analysisMetrics,
  formatDuration,
  MODE_DETAILS,
  normalizeMode,
  offloadSummary,
  ownershipStateLabel,
  visibleFileRows,
} from "../dist/insights.js";
import { expiryPresentation } from "../dist/quarantine.js";
import { clauseLabel, planSummary, sortedInsights, targetBytes } from "../dist/planner.js";

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
ok(referenceRootFor("/Archive/Masters/photo.raw", ["/Archive/Masters"]) === "/Archive/Masters", "reference roots cover descendants");
ok(referenceRootFor("/Archive", ["/Archive/Masters"]) === "/Archive/Masters", "reference roots protect ancestor deletion too");
ok(referenceRootFor("/Archive/Masters-old/photo.raw", ["/Archive/Masters"]) === null, "reference roots do not cover sibling prefixes");
ok(referenceRootFor("C:\\Archive\\photo.raw", ["C:\\Archive"]) === "C:\\Archive", "reference root display policy handles Windows separators");

ok(normalizeMode("all") === "all" && normalizeMode("invented") === "cache", "scan modes reject unknown values safely");
ok(MODE_DETAILS.whole.summary.includes("not read"), "whole-disk privacy promise is explicit");
const metrics = analysisMetrics({
  inventory_files: 4,
  categories: [{ category: "Images" }],
  duplicate_reclaimable_bytes: 10,
  content_analysis_complete: true,
  duplicate_groups: [{ files: [{}, {}] }],
});
ok(metrics.inventoryFiles === 4 && metrics.duplicateGroups === 1 && metrics.duplicateFiles === 2 && metrics.complete, "analysis metrics are derived without DOM state");
ok(visibleFileRows([1, 2, 3], 2).join("") === "12", "insight result lists stay bounded");
const advanced = advancedMetrics({
  media: { groups: [{ files: [{}, {}] }] },
  intelligence: {
    ownership: [{ state: "possible-leftover" }, { state: "installed-match" }],
    projects: [{ root: "/project" }],
    forecast: { anomalies: [{ label: "Video" }] },
  },
});
ok(advanced.similarGroups === 1 && advanced.similarFiles === 2 && advanced.possibleLeftovers === 1 && advanced.projects === 1 && advanced.anomalies === 1, "advanced insight metrics are defensive and deterministic");
ok(formatDuration(59) === "59 sec" && formatDuration(120) === "2 min" && formatDuration(5400) === "1.5 hr", "regeneration duration stays compact");
ok(ownershipStateLabel("possible-leftover") === "Possible leftover" && ownershipStateLabel("unknown") === "Unresolved", "ownership labels preserve uncertainty");
ok(offloadSummary({ compiled: false }).includes("Nothing can leave") && offloadSummary({ compiled: true, configured_providers: [] }).includes("no provider"), "offload status explains the fail-closed state");

const quarantined = { id: "q1", state: "quarantined", quarantined_at: 1_000, peer_paths: ["/copy"] };
ok(!expiryPresentation(quarantined, null, 999_999).eligible, "disabled retention never exposes expiry");
ok(!expiryPresentation(quarantined, 30, 1_000 + 29 * 86_400_000).eligible, "retention deadline is enforced in presentation");
const expiry = expiryPresentation(quarantined, 30, 1_000 + 30 * 86_400_000);
ok(expiry.eligible && expiry.phrase === "expire q1", "eligible expiry carries the exact confirmation phrase");
ok(!expiryPresentation({ ...quarantined, peer_paths: [] }, 30, Number.MAX_SAFE_INTEGER).eligible, "legacy records never expose expiry");

ok(targetBytes("2.5", "GB") === 2.5 * 2 ** 30 && targetBytes("nope", "GB") === 0, "planner targets validate and convert exact units");
ok(clauseLabel({ field: "size", operator: "greater-than", value: { value: 100 } }) === "size > 100", "typed filter clauses have a readable projection");
ok(planSummary({ target_met: true, actions: [{}], estimated_reclaimable_bytes: 10, immediate_reclaimable_bytes: 5 }, human).includes("Target met · 1 action"), "cleanup plan summary distinguishes potential and immediate space");
ok(sortedInsights([{ id: "a", estimated_reclaimable_bytes: 1 }, { id: "b", estimated_reclaimable_bytes: 2 }])[0].id === "b", "query evidence sorts deterministically by value");

const html = fs.readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
const app = fs.readFileSync(new URL("../dist/app.js", import.meta.url), "utf8");
ok(app.includes('call("trash_duplicate"') && app.includes('call("action_history_list"'), "Trash and unified action history are wired to desktop commands");
ok(html.includes("Action History") && html.includes("Clear Cleanup Receipts"), "history copy distinguishes audit and recovery records");
ok(app.includes('listen("scan-root-changed"') && app.includes("state.payload?.growth"), "live refresh and snapshot growth are rendered");
for (const id of ["view-mode", "finding-search", "finding-table", "insights-wrap", "insights-content", "ask-wrap", "ask-form", "ask-query", "ask-ast", "ask-results", "plan-wrap", "plan-form", "plan-target", "plan-policy", "plan-results", "local-ai-badge", "scan-mode", "home-scan-modes", "scan-health", "copy-diagnostics", "cancel-scan", "profile-selector", "profiles-sheet", "reference-roots", "reference-roots-body", "reference-add", "history-sheet", "open-quarantine", "quarantine-sheet", "quarantine-retention", "quarantine-body", "quarantine-close", "change-notice", "refresh-snapshot", "home", "home-scan-home", "home-choose-folder", "home-update"]) {
  ok(html.includes(`id="${id}"`), `required DOM id ${id}`);
}
ok(app.includes('call("insight_query"') && app.includes('call("cleanup_plan"') && app.includes('call("local_ai_status"') && app.includes("appendAdvancedIntelligence"), "Ask, Plan, local AI, and advanced intelligence are wired to typed desktop evidence");
ok(app.includes("similar never means duplicate") && app.includes("possible leftover, never proof") && app.includes("Per-request consent required"), "M6 review and consent boundaries remain visible in the UI");

console.log(`${checks - failures}/${checks} checks passed`);
if (failures) process.exit(1);
