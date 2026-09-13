# CacheReaper v2 — Trusted Disk Intelligence

Status: implementation started 2026-08-31
Target: CacheReaper 2.x desktop and CLI
Primary platforms: macOS and Windows; keep the core portable to Linux

## 1. Product decision

CacheReaper v2 will be a local-first storage intelligence utility, not an
opaque “one-click optimizer.” It will answer three increasingly expensive
questions:

1. **Cache Scan** — what can be regenerated and safely reclaimed?
2. **Whole Disk** — what is occupying this volume or folder?
3. **All Files / Deep Scan** — which individual files are redundant, stale,
   unusually large, or otherwise worth reviewing?

The differentiator is a strict separation between **evidence**, **advice**, and
**authority**:

- scanners and deterministic classifiers produce evidence;
- ranking models and language models may explain or prioritize evidence;
- only typed actions accepted by the deterministic safety engine may change the
  filesystem;
- AI output can never add a path, weaken a guard, construct a shell command, or
  authorize deletion.

The v2 north-star metric is **verified bytes safely reclaimed per active user**.
Guardrail metrics are unrecoverable-deletion incidents, restore rate,
recommendation rejection rate, scan completion rate, time to first useful
result, estimate-vs-observed free-space delta, and peak scan resource use.

## 2. Non-negotiable safety contract

The existing guarantees remain part of the public product contract:

- dry-run remains the CLI default;
- symlinks are never followed;
- scans do not cross filesystem boundaries unless the user starts another scan;
- protected components and cloud-sync roots remain hard blocked;
- user exclusions are visible scan boundaries, not silent omissions;
- deletion targets are revalidated immediately before the action;
- an audit receipt must be durably created before destructive work begins;
- a changed, moved, replaced, or newly protected target is skipped;
- scan cancellation never publishes a partial result over the last good result.

V2 adds these constraints:

- personal files discovered by Whole Disk or Deep Scan are never passed through
  the cache purge path merely because a model recommended them;
- non-cache file removal defaults to platform Trash or a quarantine vault;
- exact duplicate claims require a complete content hash of every group member;
- “similar” never means “duplicate” and never enables automatic deletion;
- protected reference roots can participate in comparison but cannot be changed;
- all scan and insight payloads declare a schema version and scan mode;
- cloud inference is off by default and requires a per-request disclosure of
  the data that would leave the device;
- cleanup plans are immutable snapshots; execution revalidates every action.

## 3. Scan modes

### 3.1 Cache Scan (`cache`)

Purpose: fast identification of known caches, build artifacts, reinstallable
dependencies, toolchains, logs, installers, and other rule-backed targets.

Reads:

- directory metadata;
- marker filenames needed by the rule engine;
- git ignore state where a rule explicitly requires it.

Does not retain a file-level inventory or read personal file contents.

Outputs:

- the directory arena used by the treemap;
- rule findings with tier, evidence, regeneration path, and warning;
- allocated, logical, shared, and reclaimable accounting;
- scan-health boundaries and permission failures.

### 3.2 Whole Disk (`whole`)

Purpose: explain storage use across a selected root without reading file
contents.

Reads and retains file metadata:

- parent directory, filename, allocated and logical size;
- modification time and broad file category;
- file type and symlink state;
- filesystem identity required to account for hard links and clones.

Initial outputs:

- top large files;
- old large files;
- category totals;
- directory treemap and rule-backed reclaimable findings.

Later outputs:

- saved scan snapshots and growth deltas;
- application/project ownership attribution;
- purgeable, snapshot, hidden-space, and per-volume explanation;
- live incremental updates using platform filesystem notifications.

Whole Disk is read-only for unclassified files. Actions exposed from its file
views are Reveal, Preview, Open, add exclusion, and explicitly enter review for
Trash/quarantine.

### 3.3 All Files / Deep Scan (`all`)

Purpose: opt-in content analysis for redundancy and review candidates.

Deep Scan includes the Whole Disk inventory, then performs bounded analysis:

- exact duplicates: size groups, partial hash, then full content hash;
- similar media: perceptual image hashes and sampled video/audio fingerprints;
- broken files, invalid extensions, zero-byte files, and invalid symlinks;
- archive candidates and unusually large or stale files;
- local embeddings for user-approved document locations.

The first v2 slices implement exact duplicate groups using a partial-content
filter followed by full hashes, plus recoverable quarantine for a selected
duplicate member. Persistent hash caches, similar-media analysis, and semantic
indexing follow after the action/quarantine model is complete.

## 4. Core domain model

### 4.1 Versioned scan request

```text
ScanRequestV2
  schema: 2
  scan_id: UUID-like opaque identifier
  mode: cache | whole | all
  root xor profile_id
  excluded_paths[]
  excluded_rules[]
  reference_roots[]
  resource_policy
```

Clients that omit `schema` or `mode` are interpreted as the v1-compatible
`cache` request during the migration window.

### 4.2 Scan snapshot

```text
ScanSnapshotV2
  schema
  scan_id
  mode
  root identity
  started_at / finished_at
  stats and health
  directory arena
  rule findings
  insight summary
  analysis completeness
  engine/model provenance
```

The snapshot is immutable. UI filtering must not mutate it. Large inventories
will move behind paginated commands before persistent snapshots are enabled;
the initial payload returns bounded insight lists only.

### 4.3 File evidence

The scanner may retain a `FileRecord` only in Whole/All modes:

```text
parent node id, name, allocated bytes, logical bytes, mtime, file kind
```

Absolute paths are reconstructed from the directory arena. This avoids
repeating root and directory strings for every file. Content hashes are stored
only by the deep-analysis layer and are never treated as secret-free telemetry.

### 4.4 Insight

Every recommendation-capable item uses a typed evidence envelope:

```text
Insight
  id and kind
  title and explanation
  paths or node ids from scanner evidence
  estimated reclaimable bytes
  confidence
  risk and recoverability
  evidence[]
  provenance: rule | analyzer | local-model | cloud-model
  permitted actions[]
```

An explanation is presentation; the typed evidence and permitted actions are
authority. Model text cannot alter those fields.

### 4.5 Cleanup plan

```text
CleanupPlan
  snapshot id
  target bytes
  policy: safest | balanced | maximum | fastest-recovery
  immutable typed actions[]
  estimated bytes, time, bandwidth, and rebuild cost
  risks and excluded alternatives
```

Execution accepts only actions originating from a current snapshot and runs
the relevant cache, Trash, quarantine, offload, archive, or vendor-command
validator. Shell strings emitted by models are never executable actions.

## 5. Architecture

```text
Filesystem
    │
    ▼
Parallel scanner ──► immutable scan snapshot ──► deterministic analyzers
    │                                                │
    └── scan health / boundaries                     ▼
                                            typed evidence + insights
                                                       │
                           ┌───────────────────────────┴──────────────┐
                           ▼                                          ▼
                   local AI ranking                         UI/search/filter
                   and explanation                                  │
                           └───────────────────────────┬──────────────┘
                                                       ▼
                                              typed cleanup plan
                                                       │
                                                       ▼
                                   final guard + Trash/quarantine/purge
                                                       │
                                                       ▼
                                                durable receipt
```

Crate/module boundaries:

- `scan`: bounded parallel filesystem inventory and accounting;
- `mode`: versioned mode and inventory-depth contracts;
- `analysis`: deterministic large/old/category/duplicate analysis;
- `media`: bounded perceptual image and sampled audio/video similarity;
- `intelligence`: application ownership hints, project costs, trends, and anomalies;
- `rules`: cache/build-artifact classification;
- `insights`: common evidence and recommendation types;
- `plan`: goal-based cleanup plan construction;
- `guard`: final path and action validation;
- `purge`: rule-backed cache deletion only;
- `quarantine`: recoverable personal-file actions;
- `history`: receipts, restores, and observed deltas;
- `ai`: optional adapters consuming sanitized typed evidence;
- `offload`: exact disclosures and feature-gated connector contracts.

The core crate remains independent of Tauri and must be testable without a
desktop runtime.

## 6. AI capability plan

### 6.1 Evidence-backed explanation

Generate concise explanations from typed insight fields. The UI always displays
provenance, confidence, risk, recovery path, and the exact evidence behind the
text. A deterministic template is the fallback when no model is available.

### 6.2 Goal-based planner

The user asks for a target such as “free 40 GB.” The deterministic planner
constructs safe, balanced, and maximum candidate plans. A model may summarize
trade-offs but cannot edit the action set.

### 6.3 Natural-language disk query

Queries compile into an allowlisted filter AST over the local index. Examples:

- `size > 2 GB and age > 180 days`
- category is video and path is Downloads
- rule risk is low and regeneration cost is cheap
- exact duplicate has one member in a protected reference root

The compiled query is shown to the user and can be edited with normal controls.

### 6.4 Forecasts and anomalies

Saved snapshots support deterministic trends first. Statistical models later
identify runaway logs, rapidly growing simulator/device data, sudden duplicate
imports, and likely dates for low-disk pressure.

### 6.5 Project intelligence

Use manifests, lockfiles, repository state, artifact provenance, dependency
stores, and observed cleanup history to estimate regeneration time and cost.
Uncommitted source and repository metadata remain outside the action model.

### 6.6 Privacy modes

- **Private:** deterministic analyzers only.
- **Local intelligence:** local ranking, embeddings, and language model.
- **Cloud assist:** separately opt-in per request with an exact disclosure.

No mode sends paths, filenames, hashes, embeddings, scan statistics, or content
without explicit opt-in. Telemetry is not a prerequisite for AI features.

## 7. UX plan

### Home

Present three scan cards before choosing a scope. Each card states what it
reads, expected relative cost, and allowed actions. Remember the last mode but
never silently escalate from Cache/Whole to Deep Scan.

### Scan progress

Show phase (`walking`, `classifying`, `hashing`, `summarizing`), file count,
bytes observed, elapsed time, and cancellation. Deep Scan additionally shows
hash progress and supports pausing.

### Results

- Map: directory treemap with risk/category/age coloring.
- Findings: rule-backed reclaimable targets.
- Insights: large files, old large files, category totals, duplicates,
  anomalies, similar media, application ownership hints, and project costs.
- Ask: natural-language query plus the visible compiled filters.
- Plan: target-bytes cleanup planner and evidence review.

The deletion selection UI remains limited to rule findings. Exact duplicate
results expose a separate recoverable quarantine action only when backed by the
current All Files scan; they never enter the cache purge path.

### Explanation card

Every actionable card answers: what is it, why was it suggested, how much can
actually be reclaimed, confidence, risk, what might break, how to recover, and
which engine produced the conclusion.

## 8. Resource and performance budgets

Initial budgets, verified with benchmarks before release:

- Cache Scan: no file inventory; peak memory stays close to v1.
- Whole Disk: bounded results payload; target less than 200 bytes retained per
  file before allocator overhead and less than 10% foreground CPU after scan.
- Deep Scan: hashing concurrency defaults to two workers, yields to scan
  cancellation, and avoids cloud placeholders and protected roots.
- Similar media: at most 256 candidates per media kind, 64 groups per kind,
  512 MB per file, eight 16 KB byte samples for audio/video, and a 40 MP/192 MB
  image decode ceiling. Cancellation discards partial groups.
- UI payload: large/old lists are bounded to 100 entries each; duplicate groups
  are bounded until pagination is implemented.
- Hash files in streaming buffers; never read an entire file into memory.
- Do not hash unique file sizes or files below the configured threshold.
- Pause or reduce concurrency under thermal pressure or low battery where the
  platform exposes those signals.

## 9. Persistence and migrations

V2 config additions use defaults so v1 config files continue to load:

- last scan mode;
- Deep Scan minimum duplicate size;
- reference roots;
- quarantine path and retention;
- scheduled low-risk cleanup policy;
- privacy/AI mode;
- resource policy.

Persistent scan and hash indexes use their own versioned files under
`~/.cachereaper/index/`. Writes are temp-file + fsync + atomic replace. An
unknown or corrupt index is ignored and rebuilt; it never prevents startup.

Receipts remain readable across versions. New action kinds extend the schema
without rewriting historical receipts.

## 10. Delivery milestones

### M0 — Contracts and modes

- [x] Add `ScanMode` and inventory depth to the core.
- [x] Add scan schema/mode to the desktop request and payload.
- [x] Add home and header mode controls with clear privacy descriptions.
- [x] Preserve v1-compatible Cache behavior.
- [x] Unit-test mode parsing, defaults, serialization, and invalid values.

Acceptance: all three modes can be selected, survive a rescan, reach the Rust
core, and are reported in diagnostics. Cache mode does not retain file records.

### M1 — Whole Disk insights

- [x] Retain compact file records in Whole/All modes.
- [x] Produce category totals, largest files, and old-large files.
- [x] Bound and sort result lists deterministically.
- [x] Render a read-only Insights panel with Reveal actions.
- [x] Add cancellation and accounting tests.

Acceptance: a fixture scan returns exact category totals and stable top-file
ordering without reading contents.

### M2 — Exact duplicate deep scan

- [x] Group regular files by logical size and partial hash.
- [x] Stream a full hash for candidate groups.
- [x] Recheck size and modification identity around hashing.
- [x] Exclude protected roots, zero-allocation/cloud placeholders, and too-small files.
- [x] Render read-only duplicate groups with potential savings.
- [x] Implement the persistent identity/size/mtime hash cache and cache-hit/mutation fixtures.

Acceptance: Deep Scan finds byte-identical files, rejects same-size different
files, does not double-count hard links, and never exposes deletion actions.

### M3 — Recoverable personal-file actions

- [x] Add platform Trash adapter with a durable intent and explicit quarantine fallback.
- [x] Add evidence-bound, same-volume quarantine with an append-only manifest.
- [x] Add explicit restore with collision, protected-path, and content checks.
- [x] Reconcile an interrupted post-move manifest into a recoverable UI state.
- [x] Invalidate scan evidence after every successful filesystem mutation.
- [x] Protect quarantine vaults from scans and cleanup rules.
- [x] Add configurable retention with a default 30-day eligibility window.
- [x] Add manually confirmed permanent expiry with live peer revalidation.
- [x] Reconcile interrupted expiry manifests without claiming a deleted file is recoverable.
- [x] Unify cleanup receipts, quarantine manifests, and Trash transactions under an action-kind/state history projection.
- [x] Add persisted immutable reference roots across cache purge, quarantine, and restore.
- [x] Keep reference files readable for comparison and prevent ancestor-directory deletion.
- [x] Complete audit-write, unavailable-volume, and interrupted transaction failure-injection coverage.

Acceptance: every personal-file action is recoverable by default and survives
process interruption without losing its manifest.

### M4 — Snapshots and incremental index

- [x] Persist immutable scan summaries with atomic, durable publication.
- [x] Compare snapshots and attribute growth by category and directory.
- [x] Add platform change notifications and an evidence-invalidating refresh flow.
- [x] Persist content hashes keyed by stable file identity plus size/high-resolution mtime.
- [x] Add bounded index pruning and corruption/unknown-schema recovery.

Acceptance: a second unchanged scan avoids rehashing and growth reports match
fixture mutations.

### M5 — Planner and local AI

- [x] Define typed `Insight`, filter AST, and `CleanupPlan` schemas.
- [x] Implement deterministic goal-based plan generation.
- [x] Add template explanations and provenance.
- [x] Add natural-language-to-filter adapter with strict validation.
- [x] Add an optional local model runtime behind a feature flag.
- [x] Add prompt-injection and malformed-output tests.

Acceptance: disconnecting or corrupting the model cannot change permitted
actions; every accepted model response round-trips through the typed validator.

### M6 — Advanced intelligence

- [x] Perceptual image similarity.
- [x] Sampled video/audio similarity.
- [x] App ownership and leftovers.
- [x] Project regeneration-cost estimates.
- [x] Forecasting and anomaly detection.
- [x] Optional cloud/offload connectors.

Acceptance: media groups remain review-only; an application-catalog miss is
labelled possible rather than proven; forecasts need at least two snapshots and
one hour of history; connector requests require a tamper-evident itemized
disclosure and exact consent, and connector results never gain deletion
authority. All analyzers are bounded and operate locally by default.

## 11. Test strategy

### Unit and property tests

- path normalization, containment, exclusion, and protection;
- mode/inventory invariants;
- size accounting for hard links, sparse files, and simulated shared blocks;
- stable category and top-N ordering;
- duplicate hashing and mutation during hashing;
- typed model output validation;
- cleanup-plan byte totals and policy constraints.

### Integration fixtures

Build synthetic trees containing source, rule-backed artifacts, exact and false
duplicates, hard links, symlinks, sparse files, unreadable boundaries, external
mount boundaries, cloud placeholders, unicode names, long paths, and files that
change during the scan.

### Failure injection

Exercise cancellation, permission loss, audit failure, disk-full during receipt
or quarantine, process interruption, index corruption, model timeout, invalid
model output, and target replacement between scan and action.

### UI tests

Verify mode selection, privacy copy, progress phases, read-only insight actions,
selection isolation, diagnostics, keyboard navigation, reduced motion, narrow
windows, and dark/light themes.

### Release gates

- Rust core tests on macOS, Windows, and Linux;
- Python CLI parity and rule snapshot tests;
- JavaScript module tests;
- representative scan benchmarks;
- signed-update verification;
- manual permission and Full Disk Access pass on supported macOS versions;
- manual SmartScreen/install/update pass on supported Windows versions.

## 12. Rollout

1. Ship modes and read-only insights behind no experimental flag; Cache remains
   the default.
2. Label Deep Scan beta until hash caching and resource throttling are proven.
3. Ship Trash/quarantine before offering any personal-file cleanup action.
4. Ship deterministic planning before enabling any language model.
5. Ship local AI as optional; keep deterministic explanations fully supported.
6. Treat cloud AI as a separate privacy feature, not the default implementation.

## 13. Explicitly out of scope for early v2

- registry cleaning, RAM “boosting,” antivirus, or generic performance claims;
- autonomous deletion of personal files;
- uploading an entire filesystem index;
- executing AI-produced shell commands;
- following symlinks to increase scan coverage;
- deduplicating by replacing files with hard links without a specialized,
  separately reviewed transaction model;
- claiming that deleting caches inherently makes a computer faster.

## 14. First implementation slice

The initial code change following this plan is M0–M2 as one safe vertical slice:

1. add the mode and schema contracts;
2. retain compact file records only for Whole/All modes;
3. generate bounded category, large-file, old-large-file, and exact-duplicate
   insight payloads;
4. expose mode selection and read-only insight results in the desktop UI;
5. leave existing deletion behavior restricted to rule-backed findings;
6. verify with core fixtures, UI module tests, existing test suites, and release
   builds where the local toolchain permits.
