# CacheReaper 2.0.0 — Intelligent storage, with evidence

CacheReaper 2.0 expands the original cache reclaimer into a privacy-first
storage intelligence utility. It can inventory an entire disk, prove exact
duplicates locally, explain where space is going, and build reviewable cleanup
plans without giving an AI model authority over the filesystem.

## Highlights

- Three explicit scan modes: fast **Cache Scan**, metadata-only **Whole Disk**,
  and local-content **All Files** analysis. CacheReaper never silently escalates
  from one inspection level to another.
- Whole-disk storage categories, largest and old-large-file views, bounded
  payloads, allocated-versus-logical accounting, and clear unreadable/excluded
  boundaries.
- Exact duplicate proof using size filtering, partial hashes, and complete
  SHA-256 hashes. Hard links are not counted as reclaimable copies.
- Recoverable personal-file handling through native system Trash or a
  same-volume quarantine vault, with revalidation, append-only transaction
  records, safe restore, explicit retention, and protected reference roots.
- Immutable local scan snapshots, incremental hash reuse, directory/category
  growth comparisons, filesystem-change invalidation, robust growth forecasts,
  and anomaly detection.
- A typed **Ask** workspace and deterministic goal-based **Plan** workspace.
  Optional local-model output is presentation-only and cannot add paths or
  actions.
- Review-only perceptual image similarity and sampled audio/video similarity,
  cautious application ownership and possible-leftover hints, plus regeneration
  cost estimates for common project ecosystems.
- A feature-gated offload connector contract with itemized, tamper-evident
  disclosures and exact per-request consent. No cloud provider is configured and
  nothing is uploaded by default.

## Safety and privacy

- Similar media is never treated as an exact duplicate and never enables an
  automatic file action.
- An application-catalog miss is labelled a possible leftover, not proof that an
  application was removed.
- Forecasts, anomalies, planner output, and model-generated explanations are not
  deletion authority.
- Whole Disk does not read personal-file contents. All Files streams candidate
  content locally with bounded memory. Cache Scan retains no personal-file
  inventory.
- Every destructive operation is validated again against the current snapshot,
  allowed roots, protected paths, filesystem identity, and recovery policy.

## Upgrading

Existing desktop installations from 1.5 or later should offer 2.0.0 through the
built-in updater. Earlier desktop versions should install the latest package
manually. The Python CLI can update itself with `cachereaper update --install`.

Saved v1 configuration remains compatible. New fields use conservative defaults,
and corrupt or newer local index files are ignored and rebuilt rather than
blocking startup.

## Verification

The release candidate passed 122 Rust core tests, the desktop integration test,
133 frontend checks, 44 Python CLI tests, strict Clippy checks, minimal-feature
compilation, and an optimized all-features release build.
